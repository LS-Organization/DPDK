// udp_rtt_client.cpp
// Kernel-UDP RTT client with --time N seconds stop condition (sockperf-like),
// precise pacing, ARP warm-up, interface/src binding, and percentile summary.
//
// Build:
//   g++ -O3 -std=c++17 udp_rtt_client.cpp -o udp_rtt_client
//
// Examples:
//   # run for 20s, ~10k pps, ~200k packets total
//   ./udp_rtt_client --dst 172.30.53.191 --port 9000 --size 64 --rate 10000 --time 20
//
//   # run for exactly 100k packets (no time limit)
//   ./udp_rtt_client --dst 172.30.53.191 --port 9000 --size 64 --rate 10000 --count 100000
//
// Notes:
// - If both --time and --count are provided, --time TAKES PRIORITY and the tool stops by time.
// - Use --iface IFNAME to bind to a NIC (root required for SO_BINDTODEVICE).
// - Uses CLOCK_MONOTONIC_RAW and absolute clock_nanosleep for stable pacing.

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <string>
#include <csignal>

static volatile bool g_stop = false;

static void sig_handler(int) {
    g_stop = true;
}

static inline uint64_t nsec_now() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t res = uint64_t(ts.tv_sec) * 1000'000'000ull + ts.tv_nsec;
    ///std::cout << "ts.sec " << ts.tv_sec << " nsec " << ts.tv_nsec << " res " << res << std::endl;
    return res;
}

static inline void sleep_until_ns(uint64_t abs_ns) {
    timespec ts;
    ts.tv_sec  = abs_ns / 1000'000'000ull;
    ts.tv_nsec = abs_ns % 1000'000'000ull;
    while (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, nullptr) == EINTR)
    {}
}

static void usage(const char* p) {
    std::cerr <<
      "Usage: " << p << " --dst A.B.C.D --port N [--size BYTES] [--rate PPS]\n"
      "                 [--time SECONDS] [--count NUM]\n"
      "                 [--iface IFNAME] [--src-ip A.B.C.D] [--src-port N]\n"
      "                 [--ttl N] [--tos N] [--busy-poll US]\n"
      "Notes:\n"
      "  If both --time and --count are given, --time takes priority.\n"
      "Examples:\n"
      "  " << p << " --dst 172.30.53.191 --port 9000 --size 64 --rate 10000 --time 20\n";
}

int main(int argc, char** argv) {
    std::signal(SIGINT,  sig_handler);
    std::signal(SIGTERM, sig_handler);

    const char* dst_ip   = nullptr;
    const char* src_ip   = nullptr;
    const char* iface    = nullptr;
    int   dst_port   = 0;
    int   src_port   = 0;
    int   payload_sz = 64;       // UDP payload bytes
    int   pps        = 10000;    // packets per second
    long  count      = 0;        // total packets (0 => ignore if --time given)
    double run_secs  = 0.0;      // 0 => disabled (use --count)
    int   ttl        = 0;        // 0 => don't set
    int   tos        = -1;       // -1 => don't set
    int   busy_poll  = 0;        // microseconds, 0 => disabled

    // Parse args (supports --k v and --k=v forms)
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        const char* val = nullptr;
        const char* eq  = strchr(arg, '=');

        auto next_val = [&](int& iref) -> const char* {
            if (eq)
                return eq + 1;
            if (iref + 1 < argc)
                return argv[++iref];
            usage(argv[0]); exit(1);
        };

        auto is = [&](const char* k) {
            return (strcmp(arg,k)==0) || (eq && strncmp(arg,k,strlen(k))==0);
        };

        if (is("--dst"))        dst_ip   = next_val(i);
        else if (is("--port"))  dst_port = atoi(next_val(i));
        else if (is("--size"))  payload_sz = atoi(next_val(i));
        else if (is("--rate"))  pps = atoi(next_val(i));
        else if (is("--count")) count = atol(next_val(i));
        else if (is("--time"))  run_secs = atof(next_val(i));
        else if (is("--iface")) iface = next_val(i);
        else if (is("--src-ip"))   src_ip = next_val(i);
        else if (is("--src-port")) src_port = atoi(next_val(i));
        else if (is("--ttl"))      ttl = atoi(next_val(i));
        else if (is("--tos"))      tos = atoi(next_val(i));
        else if (is("--busy-poll")) busy_poll = atoi(next_val(i));
        else if (!strcmp(arg,"-h") || !strcmp(arg,"--help")) { usage(argv[0]); return 0; }
        // unknown flags ignored
    }

    if (!dst_ip ||
        dst_port <= 0 ||
        payload_sz <= 0 ||
        pps <= 0 ||
        (run_secs <= 0.0 && count <= 0)) {
        usage(argv[0]);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket"); return 1;
    }

#ifdef SO_BINDTODEVICE
    std::cout << "SO_BINDTODEVICE" << std::endl;
    if (iface && *iface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) != 0) {
            perror("setsockopt(SO_BINDTODEVICE)"); /* non-fatal */
        }
    }
#endif

    if (src_ip || src_port > 0) {
        sockaddr_in src{.sin_family{AF_INET}, .sin_port{::htons(src_port)}};
        // src.sin_family = AF_INET;
        // src.sin_port = ::htons(src_port);
        if (src_ip && inet_aton(src_ip, &src.sin_addr) == 0) {
            std::cerr << "bad --src-ip\n";
            close(fd);
            return 1;
        }
        if (bind(fd, (sockaddr*)&src, sizeof(src)) != 0) {
            perror("bind(src)"); /* non-fatal, but be aware */
        }
    }

    int buf = 1<<20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    timeval tv{.tv_sec=1, .tv_usec=0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

#ifdef SO_BUSY_POLL
    std::cout << "SO_BUSY_POLL" << std::endl;
    if (busy_poll > 0)
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
#endif
    if (ttl > 0)
        setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (tos >= 0)
        setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    std::cout << "SOCKET READY" << std::endl;

    sockaddr_in dst{.sin_family{AF_INET}, .sin_port{::htons(dst_port)}};
    // dst.sin_family = AF_INET;
    // dst.sin_port = htons(dst_port);
    if (inet_aton(dst_ip, &dst.sin_addr) == 0) {
        std::cerr << "bad --dst\n";
        close(fd);
        return 1;
    }
    if (connect(fd, (sockaddr*)&dst, sizeof(dst)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    std::cout << "CONNECT READY" << std::endl;

    static constexpr uint32_t sMagic{0xCAFEBABE};
    struct Meta {
        uint64_t send_ns;
        uint32_t seq;
        uint32_t magic{sMagic};

        Meta() = default;
        Meta(uint64_t nanos, uint32_t seq_num) : send_ns{nanos}, seq{seq_num} {}

        [[nodiscard]] std::string toString(bool verbose = false) const {
            std::string magic_str{""};
            if (verbose) {
                magic_str = " magic " + std::to_string(magic);
            }
            std::string res{"nanos "};
            return res + std::to_string(send_ns) + " seq " + std::to_string(seq) + magic_str;
        }
    };

    std::vector<uint8_t> payload(payload_sz, 0);
    std::vector<uint64_t> rtts;
    rtts.reserve(run_secs > 0 ? size_t(pps * run_secs * 1.1) : size_t(count));
    long sent_ok = 0, recv_ok = 0, recv_nothing = 0, timeouts = 0;

    // Warm-up (helps ARP/neigh)
    for (int i = 0; i < 10; ++i) {
        Meta m{nsec_now(), i};
        ///m.send_ns = nsec_now();
        ///m.seq = 0xFFFF0000u | i;
        ///m.magic = 0xCAFEBABE;
        ::memcpy(payload.data(), &m, std::min<int>(payload_sz, (int)sizeof(Meta)));
        (void)send(fd, payload.data(), payload.size(), 0);


        uint8_t arp_buf_rx[65536]{};
        ssize_t r_arp = ::recv(fd, arp_buf_rx, sizeof(arp_buf_rx), 0);
        if (r_arp >= (ssize_t)sizeof(Meta)) {
            Meta arp_rm{};
            ::memcpy(&arp_rm, arp_buf_rx, sizeof(Meta));
            if (!(arp_rm.magic == sMagic && arp_rm.seq == (uint32_t)i)) {
                std::cout << "ARP recv msg malfmt, sent [" << m.toString(true) << "] recv [" << arp_rm.toString(true) << "]\n";
            }
        } else if (r_arp >= 0) {
            std::cout << "ARP recv nothing" << std::endl;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) timeouts++;
            // errors other than timeout are ignored to keep test running
        }

        std::cout << m.toString() << std::endl;
        ::usleep(5000);
    }

    const uint64_t interval_ns = 1000'000'000ull / (uint64_t)pps;
    uint64_t next_deadline = nsec_now() + interval_ns;

    const uint64_t start_ns = nsec_now();
    const uint64_t stop_ns  = (run_secs > 0.0) ? (start_ns + (uint64_t)(run_secs * 1e9)) : 0;

    std::cout << "Interval " << interval_ns << " deadline " << next_deadline
              << " start nanos " << start_ns << " stop nanos " << stop_ns << std::endl;

    // Progress heartbeat (once per second)
    uint64_t last_heartbeat = start_ns;

    for (long i = 0; !g_stop; ++i) {
        if (run_secs > 0.0 && nsec_now() >= stop_ns)
            break;

        if (run_secs <= 0.0 && count > 0 && i >= count)
            break;

        Meta m{nsec_now(), i};
        /// m.seq = (uint32_t)i;
        /// m.magic = 0xCAFEBABE;
        /// m.send_ns = nsec_now();

        ::memcpy(payload.data(), &m, std::min<int>(payload_sz, (int)sizeof(Meta)));

        ssize_t s = ::send(fd, payload.data(), payload.size(), 0);
        if (s >= 0)
            sent_ok++;
        else {
            ::perror("send");
            std::cout << "Send failed " << m.toString() << std::endl;
            continue;
        }

        uint8_t buf_rx[65536]{};
        ssize_t r = ::recv(fd, buf_rx, sizeof(buf_rx), 0);
        uint64_t recv_ns = nsec_now();

        if (r >= (ssize_t)sizeof(Meta)) {
            Meta rm{};
            ::memcpy(&rm, buf_rx, sizeof(Meta));
            uint64_t base_nanos{0};
            if (rm.magic == sMagic && rm.seq == (uint32_t)i) {
                base_nanos = rm.send_ns;
            } else {
                base_nanos = m.send_ns;
                std::cout << "Recv msg malfmt, sent [" << m.toString(true) << "] recv [" << rm.toString(true) << "]\n";
            }
            rtts.push_back(recv_ns - base_nanos);
            recv_ok++;
        } else if (r >= 0) {
            rtts.push_back(recv_ns - m.send_ns);
            recv_nothing++;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) timeouts++;
            // errors other than timeout are ignored to keep test running
        }

        // heartbeat
        if (recv_ns - last_heartbeat >= 1000'000'000ull) {
            std::cout << "[progress] sent=" << sent_ok << " recv_ok=" << recv_ok << " recv_nothing=" << recv_nothing
                      << " timeouts=" << timeouts << "\n";
            last_heartbeat = recv_ns;
        }

        next_deadline += interval_ns;
        sleep_until_ns(next_deadline);
    }

    std::cout << "Sent=" << sent_ok << " Recv=" << recv_ok << " Recv_nothing=" << recv_nothing << " Timeouts=" << timeouts << "\n";
    if (!rtts.empty()) {
        std::sort(rtts.begin(), rtts.end());
        auto pct = [&](double p){
            size_t idx = std::min<size_t>(rtts.size()-1, (size_t)((p/100.0)*rtts.size()));
            return rtts[idx] / 1000.0; // ns -> us
        };
        double p50 = pct(50), p99 = pct(99), p999 = pct(99.9), p9999 = pct(99.99);
        double pmin = rtts.front() / 1000.0, pmax = rtts.back() / 1000.0;
        std::cout << "RTT(us): p50=" << p50
                  << " p99=" << p99
                  << " p99.9=" << p999
                  << " p99.99=" << p9999
                  << " min=" << pmin
                  << " max=" << pmax << "\n";
    } else {
        std::cout << "No RTT samples collected.\n";
    }

    close(fd);
    return 0;
}
