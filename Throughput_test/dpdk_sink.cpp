// dpdk_sink.cpp
// DPDK UDP sink for A/B with kernel_udp_sink.
// Device init mirrors dpdk_udp_echo. Parsing/statistics mirror kernel_udp_sink.
// Payload: [magic:u64(be)][seq:u64(be)][padding...]
//
// Build:
//   g++ -O3 -std=c++17 dpdk_sink.cpp -o dpdk_sink $(pkg-config --cflags --libs libdpdk)
//
// Run (A/B sanity):
//   # open filters but keep ARP so sender learns MAC
//   sudo ./dpdk_sink -l 1 -n 4 -- \
//     --port-id 0 --arp-ip 172.30.53.191 --ip 0.0.0.0 --udp 0 --payload-size 64
//
//   # then apply your real filters
//   sudo ./dpdk_sink -l 1 -n 4 -- \
//     --port-id 0 --arp-ip 172.30.53.191 --ip 172.30.53.191 --udp 9000 --payload-size 64
//
// Notes:
// - No VLAN/QinQ popping here (same as dpdk_udp_echo). Add if needed.

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <algorithm>

static volatile bool g_stop = false;

// Filters
static uint16_t g_port_id = 0;
static uint32_t g_filter_ip_be  = 0;  // 0=ANY
static uint16_t g_filter_udp_be = 0;  // 0=ANY

// ARP responder IP (independent of filters)
static uint32_t g_arp_ip_be = 0;      // 0=disabled

// Stats config
static int  g_payload_hint = 64;      // bytes, for THR calc
static bool g_quiet = false;

// Payload magic (BE on the wire)
static constexpr uint64_t kMagicBE64 = 0xBADC0FFEE0DDF00DULL;

static void on_sig(int){ g_stop = true; }

static void usage_and_exit(const char* prog) {
    std::printf(
        "Usage:\n"
        "  %s EAL_ARGS -- --port-id N [--ip A.B.C.D] [--udp PORT]\n"
        "               [--arp-ip A.B.C.D] [--no-arp] [--payload-size B] [--quiet]\n"
        "Notes:\n"
        "  --ip 0.0.0.0 => no IP filter; --udp 0 => no UDP filter\n"
        "  --arp-ip replies ARP for that IPv4 regardless of filters\n",
        prog);
    std::exit(1);
}

// accept "--key value" and "--key=value"
static bool parse_kv(const char* arg, const char* key, const char** out) {
    const size_t klen = std::strlen(key);
    if (std::strncmp(arg, key, klen) != 0) return false;
    if (arg[klen] == '=') { *out = arg + klen + 1; return true; }
    return false;
}

static inline uint64_t be64_to_host(uint64_t be) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&be);
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

int main(int argc, char** argv) {
    std::signal(SIGINT,  on_sig);
    std::signal(SIGTERM, on_sig);

    // --- EAL init (echo-style) ---
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    // --- app args ---
    bool disable_arp = false;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        const char* val = nullptr;

        if (!std::strcmp(a, "--port-id") && i+1 < argc) { g_port_id = (uint16_t)std::atoi(argv[++i]); continue; }
        if (!std::strcmp(a, "--ip") && i+1 < argc) {
            in_addr t{}; if (inet_aton(argv[++i], &t) == 0) usage_and_exit(argv[0]);
            g_filter_ip_be = t.s_addr; continue;
        }
        if (!std::strcmp(a, "--udp") && i+1 < argc) { g_filter_udp_be = htons((uint16_t)std::atoi(argv[++i])); continue; }
        if (!std::strcmp(a, "--arp-ip") && i+1 < argc) {
            in_addr t{}; if (inet_aton(argv[++i], &t) == 0) usage_and_exit(argv[0]);
            g_arp_ip_be = t.s_addr; continue;
        }
        if (!std::strcmp(a, "--no-arp")) { disable_arp = true; continue; }
        if (!std::strcmp(a, "--payload-size") && i+1 < argc) { g_payload_hint = std::max(1, std::atoi(argv[++i])); continue; }
        if (!std::strcmp(a, "--quiet")) { g_quiet = true; continue; }
        if (!std::strcmp(a, "-h") || !std::strcmp(a, "--help")) usage_and_exit(argv[0]);

        if (parse_kv(a, "--port-id", &val)) { g_port_id = (uint16_t)std::atoi(val); continue; }
        if (parse_kv(a, "--ip", &val))      { in_addr t{}; if (inet_aton(val, &t) == 0) usage_and_exit(argv[0]); g_filter_ip_be = t.s_addr; continue; }
        if (parse_kv(a, "--udp", &val))     { g_filter_udp_be = htons((uint16_t)std::atoi(val)); continue; }
        if (parse_kv(a, "--arp-ip", &val))  { in_addr t{}; if (inet_aton(val, &t) == 0) usage_and_exit(argv[0]); g_arp_ip_be = t.s_addr; continue; }
        if (parse_kv(a, "--payload-size", &val)) { g_payload_hint = std::max(1, std::atoi(val)); continue; }
    }
    if (disable_arp) g_arp_ip_be = 0;

    // --- dev caps (echo-style) ---
    rte_eth_dev_info dev_info{}; rte_eth_dev_info_get(g_port_id, &dev_info);
    const uint64_t DESIRED = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    uint64_t port_tx_offloads  = dev_info.tx_offload_capa       & DESIRED;
    uint64_t queue_tx_offloads = dev_info.tx_queue_offload_capa & DESIRED;

    // --- configure 1 RX / 1 TX (TX only for ARP replies) ---
    rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode  = RTE_ETH_MQ_RX_NONE;
    port_conf.txmode.mq_mode  = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads = port_tx_offloads;
    if (rte_eth_dev_configure(g_port_id, 1, 1, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure failed\n");

    uint16_t rx_desc = 1024, tx_desc = 1024;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(g_port_id, &rx_desc, &tx_desc) != 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_adjust_nb_rx_tx_desc failed\n");

    // --- mempool ---
    constexpr unsigned NB_MBUFS = 8192;
    rte_mempool* mp = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUFS, 256, 0,
                                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mp) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    // --- queues ---
    rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
    rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = queue_tx_offloads; // harmless

    if (rte_eth_rx_queue_setup(g_port_id, 0, rx_desc, rte_eth_dev_socket_id(g_port_id), &rxq_conf, mp) < 0)
        rte_exit(EXIT_FAILURE, "rx_queue_setup failed\n");
    if (rte_eth_tx_queue_setup(g_port_id, 0, tx_desc, rte_eth_dev_socket_id(g_port_id), &txq_conf) < 0)
        rte_exit(EXIT_FAILURE, "tx_queue_setup failed\n");

    if (rte_eth_dev_start(g_port_id) < 0)
        rte_exit(EXIT_FAILURE, "eth_dev_start failed\n");

    rte_eth_promiscuous_enable(g_port_id);

    // --- link & MAC ---
    rte_ether_addr mac{}; rte_eth_macaddr_get(g_port_id, &mac);
    rte_eth_link link{};  rte_eth_link_get_nowait(g_port_id, &link);
    char ip_filter_str[32]={0}; if (g_filter_ip_be) inet_ntop(AF_INET, &g_filter_ip_be, ip_filter_str, sizeof(ip_filter_str));
    char ip_arp_str[32]={0};    if (g_arp_ip_be)    inet_ntop(AF_INET, &g_arp_ip_be,   ip_arp_str,    sizeof(ip_arp_str));

    if (!g_quiet) {
        std::printf("DPDK sink | port=%u | filter ip=%s udp=%u | ARP-ip=%s\n",
            g_port_id, (g_filter_ip_be?ip_filter_str:"ANY"),
            (unsigned)ntohs(g_filter_udp_be), (g_arp_ip_be?ip_arp_str:"DISABLED"));
        std::printf("Link: %s, speed=%u Mbps, duplex=%s; RXdesc=%u TXdesc=%u; MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
            (link.link_status ? "UP" : "DOWN"), link.link_speed, (link.link_duplex ? "FULL" : "HALF"),
            rx_desc, tx_desc,
            mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
            mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
        std::printf("TX offloads (port)=0x%llx queue=0x%llx\n",
            (unsigned long long)port_tx_offloads, (unsigned long long)queue_tx_offloads);
    }

    // --- counters (identical semantics to kernel_udp_sink) ---
    uint64_t total_rx=0, total_ok=0, total_gap=0, total_ooo=0, bad_magic=0, too_short=0;
    uint64_t expected=0; bool have_first=false;

    uint64_t last_print = rte_rdtsc();
    uint64_t last_rx_snap = 0;
    const uint64_t hz = rte_get_tsc_hz();

    // --- main loop ---
    constexpr uint16_t BURST = 64;
    rte_mbuf* bufs[BURST];

    while (!g_stop) {
        const uint16_t n = rte_eth_rx_burst(g_port_id, 0, bufs, BURST);

        if (n == 0) {
            // periodic print
            const uint64_t now = rte_rdtsc();
            if (now - last_print >= hz) {
                const uint64_t rx_now = total_rx - last_rx_snap;
                last_rx_snap = total_rx;
                last_print = now;

                const double pps  = (double)rx_now;
                const double mbit = pps * g_payload_hint * 8.0 / 1e6;
                const double drop = (total_ok + total_gap)
                                  ? (100.0 * (double)total_gap / (double)(total_ok + total_gap))
                                  : 0.0;

                rte_eth_stats st{}; rte_eth_stats_get(g_port_id, &st);
                std::printf("RX=%" PRIu64 " OK=%" PRIu64 " GAP=%" PRIu64 " OOO=%" PRIu64
                            " | PPS=%.0f DROP=%0.5f%% THR=%.1f Mb/s"
                            " | badMagic=%" PRIu64 " short=%" PRIu64
                            " | drv ipk=%" PRIu64 " imiss=%" PRIu64 " ierr=%" PRIu64 "\n",
                            total_rx, total_ok, total_gap, total_ooo,
                            pps, drop, mbit,
                            bad_magic, too_short,
                            (uint64_t)st.ipackets, (uint64_t)st.imissed, (uint64_t)st.ierrors);
            }
            rte_pause();
            continue;
        }

        total_rx += n;

        for (uint16_t i=0; i<n; ++i) {
            rte_mbuf* m = bufs[i];
            uint8_t* p  = rte_pktmbuf_mtod(m, uint8_t*);
            const uint16_t len = rte_pktmbuf_pkt_len(m);

            if (len < sizeof(rte_ether_hdr)) { rte_pktmbuf_free(m); continue; }
            auto* eth = reinterpret_cast<rte_ether_hdr*>(p);

            // ARP reply if requested (no VLAN)
            if (g_arp_ip_be && eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                if (len >= sizeof(rte_ether_hdr) + sizeof(rte_arp_hdr)) {
                    auto* arp = reinterpret_cast<rte_arp_hdr*>(eth + 1);
                    if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) &&
                        arp->arp_data.arp_tip == g_arp_ip_be) {

                        rte_ether_addr sender = arp->arp_data.arp_sha;
                        uint32_t sender_ip    = arp->arp_data.arp_sip;

                        arp->arp_opcode       = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
                        arp->arp_data.arp_tha = sender;
                        arp->arp_data.arp_tip = sender_ip;
                        arp->arp_data.arp_sha = mac;
                        arp->arp_data.arp_sip = g_arp_ip_be;

                        eth->dst_addr = sender;
                        eth->src_addr = mac;

                        (void)rte_eth_tx_burst(g_port_id, 0, &m, 1);
                        continue; // mbuf consumed
                    }
                }
                rte_pktmbuf_free(m);
                continue;
            }

            // IPv4 only (no VLAN)
            if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { rte_pktmbuf_free(m); continue; }
            if (len < sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr)) { rte_pktmbuf_free(m); continue; }

            auto* ip4 = reinterpret_cast<rte_ipv4_hdr*>(eth + 1);
            if ((ip4->version_ihl >> 4) != 4) { rte_pktmbuf_free(m); continue; }
            const uint16_t ihl = (ip4->version_ihl & 0x0F) * 4;
            if (ihl < sizeof(rte_ipv4_hdr)) { rte_pktmbuf_free(m); continue; }
            if (ip4->next_proto_id != IPPROTO_UDP) { rte_pktmbuf_free(m); continue; }

            if (g_filter_ip_be && ip4->dst_addr != g_filter_ip_be) { rte_pktmbuf_free(m); continue; }
            if (len < sizeof(rte_ether_hdr) + ihl + sizeof(rte_udp_hdr)) { rte_pktmbuf_free(m); continue; }

            auto* udp = reinterpret_cast<rte_udp_hdr*>(p + sizeof(rte_ether_hdr) + ihl);
            if (g_filter_udp_be && udp->dst_port != g_filter_udp_be) { rte_pktmbuf_free(m); continue; }

            const uint16_t l4_off = sizeof(rte_ether_hdr) + ihl + sizeof(rte_udp_hdr);
            if (len < l4_off + 16) { ++too_short; rte_pktmbuf_free(m); continue; }

            // ----- kernel_udp_sink logic starts (identical semantics) -----
            uint64_t magic_be=0, seq_be=0;
            std::memcpy(&magic_be, p + l4_off, 8);
            if (be64_to_host(magic_be) != kMagicBE64) { ++bad_magic; rte_pktmbuf_free(m); continue; }

            std::memcpy(&seq_be, p + l4_off + 8, 8);
            const uint64_t seq = be64_to_host(seq_be);

            if (!have_first) { expected = seq; have_first = true; }

            if (seq == expected) { ++total_ok; ++expected; }
            else if (seq > expected) { total_gap += (seq - expected); ++total_ok; expected = seq + 1; }
            else { ++total_ooo; }
            // ----- kernel logic ends -----

            rte_pktmbuf_free(m);
        }

        // periodic print
        const uint64_t now = rte_rdtsc();
        if (now - last_print >= hz) {
            const uint64_t rx_now = total_rx - last_rx_snap;
            last_rx_snap = total_rx;
            last_print = now;

            const double pps  = (double)rx_now;
            const double mbit = pps * g_payload_hint * 8.0 / 1e6;
            const double drop = (total_ok + total_gap)
                              ? (100.0 * (double)total_gap / (double)(total_ok + total_gap))
                              : 0.0;

            rte_eth_stats st{}; rte_eth_stats_get(g_port_id, &st);
            std::printf("RX=%" PRIu64 " OK=%" PRIu64 " GAP=%" PRIu64 " OOO=%" PRIu64
                        " | PPS=%.0f DROP=%0.5f%% THR=%.1f Mb/s"
                        " | badMagic=%" PRIu64 " short=%" PRIu64
                        " | drv ipk=%" PRIu64 " imiss=%" PRIu64 " ierr=%" PRIu64 "\n",
                        total_rx, total_ok, total_gap, total_ooo,
                        pps, drop, mbit,
                        bad_magic, too_short,
                        (uint64_t)st.ipackets, (uint64_t)st.imissed, (uint64_t)st.ierrors);
        }
    }

    rte_eth_dev_stop(g_port_id);
    rte_eth_dev_close(g_port_id);
    return 0;
}
