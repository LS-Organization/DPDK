// kernel_udp_sink.cpp
// Firehose payload: [magic:u64(be)][seq:u64(be)][padding...]

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

static volatile bool g_stop = false;

// 8B magic + 8B seq in big-endian
static constexpr uint64_t kMagicBE64 = 0xBADC0FFEE0DDF00DULL;

static inline uint64_t now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

static void on_sigint(int) { g_stop = true; }

static void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
    std::exit(1);
}

struct Args {
    std::string ip        = "0.0.0.0";
    uint16_t    port      = 9000;
    std::string iface     = "";      // SO_BINDTODEVICE
    int         batch     = 256;     // recvmmsg vector
    int         busy_poll = 0;       // us
    int         busy_budget = 0;     // packets
    int         rcvbuf_mb = 64;      // MB
    int         payload_hint = 64;   // for THR calc
    bool        quiet = false;
};

static void parse_args(int argc, char** argv, Args& a) {
    for (int i=1; i<argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int i){ if (i+1>=argc) die("missing value after %s", s.c_str()); };
        if (s == "--ip")           { need(i); a.ip = argv[++i]; }
        else if (s == "--port")    { need(i); a.port = (uint16_t)std::stoi(argv[++i]); }
        else if (s == "--iface")   { need(i); a.iface = argv[++i]; }
        else if (s == "--batch")   { need(i); a.batch = std::max(1, std::stoi(argv[++i])); }
        else if (s == "--busy-poll")     { need(i); a.busy_poll = std::stoi(argv[++i]); }
        else if (s == "--busy-budget")   { need(i); a.busy_budget = std::stoi(argv[++i]); }
        else if (s == "--rcvbuf")  { need(i); a.rcvbuf_mb = std::max(1, std::stoi(argv[++i])); }
        else if (s == "--payload-hint") { need(i); a.payload_hint = std::max(1, std::stoi(argv[++i])); }
        else if (s == "--quiet")   { a.quiet = true; }
        else if (s == "-h" || s=="--help") {
            std::printf(
                "Kernel UDP sink (DPDK-like, 8B magic + 8B seq BE) options:\n"
                "  --ip A.B.C.D         local bind IP (default 0.0.0.0)\n"
                "  --port N             UDP port (default 9000)\n"
                "  --iface NAME         SO_BINDTODEVICE to NIC (e.g., ens6)\n"
                "  --batch N            recvmmsg vector size (default 256)\n"
                "  --busy-poll us       SO_BUSY_POLL microseconds (default 0)\n"
                "  --busy-budget pkts   SO_BUSY_POLL_BUDGET packets (default 0)\n"
                "  --rcvbuf MB          SO_RCVBUF in MB (default 64)\n"
                "  --payload-hint B     expected payload size (for THR calc, default 64)\n"
                "  --quiet              less verbose\n"
            );
            std::exit(0);
        }
    }
}

// big-endian 64 -> host
static inline uint64_t be64_to_host(uint64_t be) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&be);
    return ( (uint64_t)p[0] << 56 ) |
           ( (uint64_t)p[1] << 48 ) |
           ( (uint64_t)p[2] << 40 ) |
           ( (uint64_t)p[3] << 32 ) |
           ( (uint64_t)p[4] << 24 ) |
           ( (uint64_t)p[5] << 16 ) |
           ( (uint64_t)p[6] <<  8 ) |
           ( (uint64_t)p[7]       );
}

int main(int argc, char** argv) {
    Args args;
    parse_args(argc, argv, args);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // ---- make UDP socket ----
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket() failed: %s", strerror(errno));

    // link to specific iface
    if (!args.iface.empty()) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, args.iface.c_str(), args.iface.size()) != 0) {
            die("setsockopt(SO_BINDTODEVICE=%s) failed: %s", args.iface.c_str(), strerror(errno));
        }
    }

    // set receive buffer size
    int rcvbuf = args.rcvbuf_mb * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        die("setsockopt(SO_RCVBUF=%dMB) failed: %s", args.rcvbuf_mb, strerror(errno));
    }

    // busy-poll
    if (args.busy_poll > 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &args.busy_poll, sizeof(int)) != 0) {
            std::fprintf(stderr, "warn: SO_BUSY_POLL failed: %s\n", strerror(errno));
        }
    }
    if (args.busy_budget > 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &args.busy_budget, sizeof(int)) != 0) {
            std::fprintf(stderr, "warn: SO_BUSY_POLL_BUDGET failed: %s\n", strerror(errno));
        }
    }

    // link ip and port
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(args.port);
    if (inet_pton(AF_INET, args.ip.c_str(), &sin.sin_addr) != 1) {
        die("inet_pton(%s) failed", args.ip.c_str());
    }
    if (bind(fd, (sockaddr*)&sin, sizeof(sin)) != 0) {
        die("bind(%s:%u) failed: %s", args.ip.c_str(), args.port, strerror(errno));
    }

    // ---- print startup info ----
    std::printf(
        "Kernel UDP sink (DPDK-like, 8Bmagic+8Bseq BE) on %s:%u (iface=%s) "
        "batch=%d busy-poll=%dus budget=%d rcvbuf=%dMB payload-hint=%d\n",
        args.ip.c_str(), args.port, args.iface.empty() ? "-" : args.iface.c_str(),
        args.batch, args.busy_poll, args.busy_budget, args.rcvbuf_mb, args.payload_hint
    );
    std::fflush(stdout);

    // ---- recvmmsg size ----
    const int BATCH = args.batch;
    std::vector<mmsghdr> msgs(BATCH);
    std::vector<iovec>   iov(BATCH);
    // limit buffer size
    const int BUF_SZ = std::max(args.payload_hint + 64, 128);
    std::vector<std::vector<uint8_t>> bufs(BATCH, std::vector<uint8_t>(BUF_SZ));
    std::vector<sockaddr_in> from(BATCH);
    std::vector<socklen_t>   fromlen(BATCH, sizeof(sockaddr_in));

    for (int i=0;i<BATCH;i++) {
        memset(&msgs[i], 0, sizeof(mmsghdr));
        memset(&from[i], 0, sizeof(sockaddr_in));
        iov[i].iov_base = bufs[i].data();
        iov[i].iov_len  = bufs[i].size();
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &from[i];
        msgs[i].msg_hdr.msg_namelen = fromlen[i];
    }

    // printing vars
    uint64_t total_rx = 0;     // received packets
    uint64_t total_ok = 0;     // arived in-order pack
    uint64_t total_gap = 0;    // lost pack (gap)
    uint64_t total_ooo = 0;    // not-in-order pack
    uint64_t bad_magic = 0;    // magic not match error
    uint64_t too_short = 0;    // less than 16B

    uint64_t expected = 0;     // next expected seq
    bool     have_first = false;

    uint64_t last_print_ns = now_ns();
    uint64_t last_rx_snap = 0;

    // main loop
    while (!g_stop) {
        int n = recvmmsg(fd, msgs.data(), BATCH, 0, nullptr);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr, "recvmmsg() failed: %s\n", strerror(errno));
            break;
        }
        if (n == 0) continue;

        for (int i=0; i<n; ++i) {
            const int len = msgs[i].msg_len;
            total_rx++;

            if (len < 16) { // 8B magic + 8B seq
                too_short++;
                continue;
            }

            const uint8_t* p = (const uint8_t*)iov[i].iov_base;

            // magic: u64 BE
            uint64_t magic_be;
            memcpy(&magic_be, p, 8);
            uint64_t magic = be64_to_host(magic_be);
            if (magic != kMagicBE64) {
                bad_magic++;
                continue;
            }

            // seq: u64 BE
            uint64_t seq_be;
            memcpy(&seq_be, p + 8, 8);
            uint64_t seq = be64_to_host(seq_be);

            if (!have_first) {
                expected = seq;
                have_first = true;
            }

            if (seq == expected) {
                total_ok++;
                expected++;
            } else if (seq > expected) {
                total_gap += (seq - expected);
                total_ok++;
                expected = seq + 1;
            } else { // seq < expected
                total_ooo++;
            }
        }

        uint64_t ns = now_ns();
        if (ns - last_print_ns >= 1'000'000'000ULL) {
            uint64_t rx_now = total_rx - last_rx_snap;
            last_rx_snap = total_rx;
            last_print_ns = ns;

            double pps = (double)rx_now;
            double mbit = pps * args.payload_hint * 8.0 / 1e6;

            std::printf(
                "RX=%" PRIu64 " OK=%" PRIu64 " GAP=%" PRIu64 " OOO=%" PRIu64
                " | PPS=%.0f DROP=%0.5f%% THR=%.1f Mb/s"
                " | badMagic=%" PRIu64 " short=%" PRIu64 "\n",
                total_rx, total_ok, total_gap, total_ooo,
                pps,
                (total_ok + total_gap) ? (100.0 * (double)total_gap / (double)(total_ok + total_gap)) : 0.0,
                mbit,
                bad_magic, too_short
            );
            std::fflush(stdout);
        }
    }

    close(fd);
    return 0;
}
