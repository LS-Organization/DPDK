// kernel_udp_echo.cpp
// A low-latency UDP echo server implemented with the Linux kernel UDP stack,
// mimicking DPDK test logic: busy-poll style, batch I/O (recvmmsg/sendmmsg),
// fixed CPU core + realtime scheduling (via chrt/taskset), per-1s counters.
//
// Build:
//   g++ -O3 -std=c++17 kernel_udp_echo.cpp -o kernel_udp_echo
//
// Run (example):
//   sudo chrt -f 99 taskset -c 2 ./kernel_udp_echo \
//       --ip 172.30.53.191 --port 9000 --iface ens6 \
//       --busy-poll 50 --busy-budget 64 --batch 32
//
// Notes:
// - Consider enabling kernel busy-poll sysctls for best effect:
//     sudo sysctl -w net.core.busy_read=50
//     sudo sysctl -w net.core.busy_poll=50
//     sudo sysctl -w net.core.busy_poll_budget=64
// - SO_BINDTODEVICE requires CAP_NET_RAW/root.
// - The server is single-threaded and non-blocking, spinning in user space
//   if recvmmsg returns EAGAIN (busy-poll-ish).

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <cinttypes>

// Some kernels support these; guard with ifdef.
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

static void usage(const char* p) {
    std::printf(
        "Usage: %s --ip A.B.C.D --port N [--iface IFNAME] [--bind-ip A.B.C.D]\n"
        "           [--tos N] [--ttl N]\n"
        "           [--busy-poll usec] [--busy-budget N] [--batch N]\n"
        "\n"
        "Example:\n"
        "  sudo chrt -f 99 taskset -c 2 %s \\\n"
        "    --ip 172.30.53.191 --port 9000 --iface ens6 \\\n"
        "    --busy-poll 50 --busy-budget 64 --batch 32\n",
        p, p);
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int main(int argc, char** argv) {
    const char* bind_ip = nullptr;   // explicit local IP to bind
    const char* iface   = nullptr;   // SO_BINDTODEVICE device
    int port = 0;
    int tos  = -1;
    int ttl  = 0;
    int busy_poll   = 0;   // microseconds
    int busy_budget = 0;   // packets per poll
    int batch       = 32;  // recvmmsg/sendmmsg batch size

    // Parse args (supports --k v and --k=v)
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        auto next = [&](const char* key)->const char*{
            const char* eq = std::strchr(a, '=');
            if (eq && std::strncmp(a, key, std::strlen(key)) == 0) return eq + 1;
            if (std::strcmp(a, key) == 0 && i + 1 < argc) return argv[++i];
            return nullptr;
        };
        if (const char* v = next("--ip"))         bind_ip = v;
        else if (const char* v2 = next("--bind-ip")) bind_ip = v2;
        else if (const char* v = next("--port"))  port = std::atoi(v);
        else if (const char* v = next("--iface")) iface = v;
        else if (const char* v = next("--tos"))   tos = std::atoi(v);
        else if (const char* v = next("--ttl"))   ttl = std::atoi(v);
        else if (const char* v = next("--busy-poll"))   busy_poll = std::atoi(v);
        else if (const char* v = next("--busy-budget")) busy_budget = std::atoi(v);
        else if (const char* v = next("--batch")) batch = std::max(1, std::atoi(v));
        else if (!std::strcmp(a, "-h") || !std::strcmp(a, "--help")) { usage(argv[0]); return 0; }
        // unknown args ignored
    }
    if (!bind_ip || port <= 0) { usage(argv[0]); return 1; }

    // Create UDP socket
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // Bind to interface (optional; requires root)
#ifdef SO_BINDTODEVICE
    if (iface && *iface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, std::strlen(iface)) != 0) {
            perror("setsockopt(SO_BINDTODEVICE)"); // non-fatal
        }
    }
#endif

    // Increase buffers (in case of bursts)
    int buf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    // Socket reuse (not strictly needed, but convenient)
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    // Prefer busy-poll in kernel if possible
#ifdef SO_PREFER_BUSY_POLL
    setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one));
#endif
#ifdef SO_BUSY_POLL
    if (busy_poll > 0) {
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    }
#endif
#ifdef SO_BUSY_POLL_BUDGET
    if (busy_budget > 0) {
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &busy_budget, sizeof(busy_budget));
    }
#endif

    if (ttl > 0) setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (tos >= 0) setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    // Bind local address
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port   = htons(port);
    if (::inet_aton(bind_ip, &local.sin_addr) == 0) {
        std::fprintf(stderr, "Invalid --ip/--bind-ip\n");
        return 1;
    }
    if (::bind(fd, (sockaddr*)&local, sizeof(local)) != 0) {
        perror("bind"); return 1;
    }

    // Non-blocking; we will spin if no packets (busy-poll-ish in user space)
    if (set_nonblock(fd) != 0) { perror("fcntl(O_NONBLOCK)"); /* continue anyway */ }

    // Pre-allocate batch structures
    const int B = batch;
    std::vector<std::vector<uint8_t>> bufs(B, std::vector<uint8_t>(2048));
    std::vector<iovec>    iov(B);
    std::vector<mmsghdr>  msgs(B);
    std::vector<sockaddr_in> peers(B);
    std::vector<unsigned>  lens(B);

    for (int i = 0; i < B; ++i) {
        iov[i].iov_base = bufs[i].data();
        iov[i].iov_len  = bufs[i].size();
        std::memset(&msgs[i], 0, sizeof(mmsghdr));
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &peers[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
    }

    // Counters and pacing
    uint64_t rx_pkts = 0, tx_pkts = 0, udp_pkts = 0;
    uint64_t last_print_ns = 0;

    auto nsec_now = []() -> uint64_t {
        timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        return uint64_t(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
    };
    last_print_ns = nsec_now();

    std::printf("Kernel UDP echo on %s:%d (iface=%s) batch=%d busy-poll=%dus budget=%d\n",
                bind_ip, port, (iface? iface : "(none)"), B, busy_poll, busy_budget);

    // Main loop: try to batch receive, echo back with sendmmsg
    while (true) {
        int n = ::recvmmsg(fd, msgs.data(), B, 0, nullptr);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Spin a little to emulate busy loop (very cheap pause)
                // Avoid calling poll()/epoll() to keep latency minimal.
                // On a real system you might use cpu_relax()/asm("pause")
                // but here usleep(0) is enough as a hint; can be removed.
                // usleep(0);
            } else {
                perror("recvmmsg");
                // continue; // keep running on transient errors
            }
        } else if (n > 0) {
            rx_pkts += n;
            udp_pkts += n;

            // Prepare replies: mirror back exactly what we got
            for (int i = 0; i < n; ++i) {
                lens[i] = msgs[i].msg_len;
                // For sendmmsg we provide the same iovec and peer address.
                // Nothing else to do: kernel fills IP/UDP headers for us.
            }

            // sendmmsg in chunks
            int sent_total = 0;
            while (sent_total < n) {
                int m = ::sendmmsg(fd, &msgs[sent_total], n - sent_total, 0);
                if (m < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // congestion: small spin
                        // usleep(0);
                        continue;
                    } else {
                        perror("sendmmsg");
                        break;
                    }
                } else {
                    tx_pkts += m;
                    sent_total += m;
                }
            }

            // Re-arm mmsghdr for next recvmmsg
            for (int i = 0; i < n; ++i) {
                msgs[i].msg_len = 0;
                msgs[i].msg_hdr.msg_name = &peers[i];
                msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                msgs[i].msg_hdr.msg_iov = &iov[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }
        }

        // 1-second stats
        uint64_t now = nsec_now();
        if (now - last_print_ns >= 1000000000ull) {
            std::printf("RX=%" PRIu64 " UDP=%" PRIu64 " TX=%" PRIu64 "\n",
                        rx_pkts, udp_pkts, tx_pkts);
            last_print_ns = now;
        }
    }

    // never reached
    // close(fd);
    // return 0;
}
