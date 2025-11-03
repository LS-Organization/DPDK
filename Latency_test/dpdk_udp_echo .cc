// dpdk_udp_echo.cc
// Robust DPDK IPv4 UDP echo with ARP responder and checksum offload fallback.
//
// Features:
// - Replies ARP who-has for --ip
// - Echoes UDP packets destined to (--ip, --udp-port) by swapping L2/L3/L4
// - TX checksums: enable NIC offload only if supported per-queue; otherwise use
//   DPDK software helpers (rte_ipv4_cksum / rte_ipv4_udptcp_cksum).
// - Auto-adjusts RX/TX descriptor counts to NIC limits (e.g., ENA <= 512).
// - Prints link info at start and RX/ARP/UDP/TX counters every second.
// - Accepts both "--opt value" and "--opt=value"; unknown flags are ignored.
//
// Build:
//   g++ dpdk_udp_echo.cc -O3 -std=c++17 $(pkg-config --cflags --libs libdpdk) -o dpdk_udp_echo
//
// Run (example):
//   sudo ./dpdk_udp_echo -l 1 -n 4 -- --port-id 0 --ip 172.30.53.191 --udp-port 9000
//
// Notes:
// - Bind the target NIC (e.g., ens6) to a DPDK driver (vfio-pci/igb_uio).
// - Make sure --port-id matches the DPDK port index returned by dpdk-devbind.py -s.

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>        // rte_ipv4_hdr, rte_ipv4_cksum, rte_ipv4_udptcp_cksum
#include <rte_udp.h>       // rte_udp_hdr
#include <rte_ether.h>
#include <rte_arp.h>       // rte_arp_hdr / rte_arp_ipv4
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>

static volatile bool g_stop = false;
static uint16_t g_port_id = 0;
static uint32_t g_local_ip_be = 0;    // IPv4 in network (big-endian)
static uint16_t g_listen_udp_be = 0;  // UDP port (big-endian)

static void handle_sig(int) { g_stop = true; }

static void usage_and_exit(const char* prog) {
    std::printf("Usage:\n  %s EAL_ARGS -- --port-id N --ip A.B.C.D --udp-port PORT\n", prog);
    std::printf("  Supports '--key value' and '--key=value'; unknown options are ignored.\n");
    std::exit(1);
}

// Accept both "--key value" and "--key=value"
static bool parse_kv(const char* arg, const char* key, const char** out) {
    const size_t klen = std::strlen(key);
    if (std::strncmp(arg, key, klen) != 0) return false;
    if (arg[klen] == '=') { *out = arg + klen + 1; return true; }
    return false;
}

int main(int argc, char** argv) {
    std::signal(SIGINT,  handle_sig);
    std::signal(SIGTERM, handle_sig);

    // --- EAL init ---
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    // --- App args ---
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        const char* val = nullptr;

        if (!std::strcmp(a, "--port-id") && i+1 < argc) { g_port_id = static_cast<uint16_t>(std::atoi(argv[++i])); continue; }
        if (!std::strcmp(a, "--ip") && i+1 < argc) {
            in_addr tmp{}; if (inet_aton(argv[++i], &tmp) == 0) usage_and_exit(argv[0]);
            g_local_ip_be = tmp.s_addr; continue;
        }
        if (!std::strcmp(a, "--udp-port") && i+1 < argc) { g_listen_udp_be = htons(static_cast<uint16_t>(std::atoi(argv[++i]))); continue; }
        if (!std::strcmp(a, "-h") || !std::strcmp(a, "--help")) usage_and_exit(argv[0]);

        // --key=value forms
        if (parse_kv(a, "--port-id", &val)) { g_port_id = static_cast<uint16_t>(std::atoi(val)); continue; }
        if (parse_kv(a, "--ip", &val))       { in_addr t{}; if (inet_aton(val, &t) == 0) usage_and_exit(argv[0]); g_local_ip_be = t.s_addr; continue; }
        if (parse_kv(a, "--udp-port", &val)) { g_listen_udp_be = htons(static_cast<uint16_t>(std::atoi(val))); continue; }

        // Unknown option: ignore (safe for flags like -P)
    }
    if (g_local_ip_be == 0 || g_listen_udp_be == 0) usage_and_exit(argv[0]);

    // --- Query device caps (needed before queue setup) ---
    rte_eth_dev_info dev_info{};
    rte_eth_dev_info_get(g_port_id, &dev_info);

    // Desired TX offloads, but we will only enable what HW advertises *per-queue*
    const uint64_t DESIRED = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                             RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    uint64_t port_tx_offloads  = dev_info.tx_offload_capa        & DESIRED;
    uint64_t queue_tx_offloads = dev_info.tx_queue_offload_capa  & DESIRED;

    // --- Device configure: 1 RX / 1 TX queue ---
    rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    // Apply only port-level supported bits (some PMDs check this at configure time)
    port_conf.txmode.offloads = port_tx_offloads;

    if (rte_eth_dev_configure(g_port_id, 1, 1, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure failed\n");

    // Descriptor counts: start high then let PMD clamp (ENA will clamp to <=512)
    uint16_t rx_desc = 1024, tx_desc = 1024;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(g_port_id, &rx_desc, &tx_desc) != 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_adjust_nb_rx_tx_desc failed\n");

    // --- Mempool ---
    constexpr unsigned NB_MBUFS = 8192;
    rte_mempool* mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NB_MBUFS, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    // --- Queue setup (use device defaults; propagate per-queue offloads) ---
    rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
    rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = queue_tx_offloads;  // ONLY what the queue supports

    if (rte_eth_rx_queue_setup(g_port_id, 0, rx_desc,
            rte_eth_dev_socket_id(g_port_id), &rxq_conf, mbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "rx_queue_setup failed\n");

    if (rte_eth_tx_queue_setup(g_port_id, 0, tx_desc,
            rte_eth_dev_socket_id(g_port_id), &txq_conf) < 0)
        rte_exit(EXIT_FAILURE, "tx_queue_setup failed\n");

    if (rte_eth_dev_start(g_port_id) < 0)
        rte_exit(EXIT_FAILURE, "eth_dev_start failed\n");

    // Promiscuous to avoid surprises (VLAN/filters)
    rte_eth_promiscuous_enable(g_port_id);

    // Link & MAC
    rte_ether_addr local_mac{};
    rte_eth_macaddr_get(g_port_id, &local_mac);
    rte_eth_link link{};
    rte_eth_link_get_nowait(g_port_id, &link);

    char ip_str[32]; inet_ntop(AF_INET, &g_local_ip_be, ip_str, sizeof(ip_str));
    std::printf("DPDK UDP echo on port %u, IP %s, UDP %u\n", g_port_id, ip_str, ntohs(g_listen_udp_be));
    std::printf("Link: %s, speed=%u Mbps, duplex=%s; RXdesc=%u TXdesc=%u; MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        (link.link_status ? "UP" : "DOWN"), link.link_speed, (link.link_duplex ? "FULL" : "HALF"),
        rx_desc, tx_desc,
        local_mac.addr_bytes[0], local_mac.addr_bytes[1], local_mac.addr_bytes[2],
        local_mac.addr_bytes[3], local_mac.addr_bytes[4], local_mac.addr_bytes[5]);
    std::printf("TX offloads (port)  : 0x%llx\n", (unsigned long long)port_tx_offloads);
    std::printf("TX offloads (queue) : 0x%llx\n", (unsigned long long)queue_tx_offloads);

    // --- Main RX/TX loop ---
    constexpr uint16_t BURST = 32;
    rte_mbuf* bufs[BURST];
    uint64_t rx_pkts=0, arp_pkts=0, udp_pkts=0, tx_pkts=0;
    uint64_t last_print = rte_rdtsc();
    const uint64_t hz = rte_get_tsc_hz();

    while (!g_stop) {
        const uint16_t nb_rx = rte_eth_rx_burst(g_port_id, 0, bufs, BURST);
        if (nb_rx == 0) {
            uint64_t now = rte_rdtsc();
            if (now - last_print > hz) {
                std::printf("RX=%" PRIu64 " ARP=%" PRIu64 " UDP=%" PRIu64 " TX=%" PRIu64 "\n",
                            rx_pkts, arp_pkts, udp_pkts, tx_pkts);
                last_print = now;
            }
            rte_pause();
            continue;
        }
        rx_pkts += nb_rx;

        for (uint16_t i = 0; i < nb_rx; ++i) {
            rte_mbuf* m = bufs[i];
            uint8_t* pkt = rte_pktmbuf_mtod(m, uint8_t*);
            const uint16_t pkt_len = rte_pktmbuf_pkt_len(m);

            if (pkt_len < sizeof(rte_ether_hdr)) { rte_pktmbuf_free(m); continue; }
            auto* eth = reinterpret_cast<rte_ether_hdr*>(pkt);

            // --- ARP ---
            if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                if (pkt_len < sizeof(rte_ether_hdr) + sizeof(rte_arp_hdr)) { rte_pktmbuf_free(m); continue; }
                auto* arp = reinterpret_cast<rte_arp_hdr*>(eth + 1);

                if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) &&
                    arp->arp_data.arp_tip == g_local_ip_be) {

                    arp_pkts++;

                    // Build ARP reply in-place
                    rte_ether_addr sender_mac = arp->arp_data.arp_sha;
                    uint32_t sender_ip = arp->arp_data.arp_sip;

                    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
                    arp->arp_data.arp_tha = sender_mac;
                    arp->arp_data.arp_tip = sender_ip;
                    arp->arp_data.arp_sha = local_mac;
                    arp->arp_data.arp_sip = g_local_ip_be;

                    eth->dst_addr = sender_mac;
                    eth->src_addr = local_mac;

                    uint16_t sent = rte_eth_tx_burst(g_port_id, 0, &m, 1);
                    tx_pkts += sent;
                    continue;
                }
                rte_pktmbuf_free(m);
                continue;
            }

            // --- IPv4 ---
            if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { rte_pktmbuf_free(m); continue; }
            if (pkt_len < sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr)) { rte_pktmbuf_free(m); continue; }

            auto* ip = reinterpret_cast<rte_ipv4_hdr*>(eth + 1);
            if ((ip->version_ihl >> 4) != 4) { rte_pktmbuf_free(m); continue; }
            const uint16_t ihl_bytes = (ip->version_ihl & 0x0F) * 4;
            if (ihl_bytes < sizeof(rte_ipv4_hdr)) { rte_pktmbuf_free(m); continue; }
            if (ip->next_proto_id != IPPROTO_UDP) { rte_pktmbuf_free(m); continue; }
            if (ip->dst_addr != g_local_ip_be) { rte_pktmbuf_free(m); continue; }
            if (pkt_len < sizeof(rte_ether_hdr) + ihl_bytes + sizeof(rte_udp_hdr)) { rte_pktmbuf_free(m); continue; }

            // --- UDP ---
            auto* udp = reinterpret_cast<rte_udp_hdr*>(reinterpret_cast<uint8_t*>(ip) + ihl_bytes);
            if (udp->dst_port != g_listen_udp_be) { rte_pktmbuf_free(m); continue; }
            udp_pkts++;

            // Swap L2/L3/L4
            rte_ether_addr tmp_mac = eth->src_addr;
            eth->src_addr = eth->dst_addr;
            eth->dst_addr = tmp_mac;

            uint32_t tmp_ip = ip->src_addr;
            ip->src_addr = ip->dst_addr;
            ip->dst_addr = tmp_ip;

            uint16_t tmp_port = udp->src_port;
            udp->src_port = udp->dst_port;
            udp->dst_port = tmp_port;

            // Set a sane TTL; total_len and udp_len unchanged (payload untouched).
            ip->time_to_live = 64;

            // Decide HW offload vs software checksum using *queue* capabilities
            const bool hw_ip  = (queue_tx_offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM);
            const bool hw_udp = (queue_tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM);

            if (hw_ip || hw_udp) {
                // HW offload path (only set flags that are truly supported)
                m->ol_flags &= ~(RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_SCTP_CKSUM |
                                 RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM |
                                 RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IPV6);
                if (hw_ip)  m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
                if (hw_udp) m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
                m->l2_len = sizeof(rte_ether_hdr);
                m->l3_len = ihl_bytes;
                m->l4_len = sizeof(rte_udp_hdr);

                // NIC computes checksums
                ip->hdr_checksum = 0;
                udp->dgram_cksum = 0;
            } else {
                // Software checksums via DPDK helpers
                ip->hdr_checksum = 0;
                ip->hdr_checksum = rte_ipv4_cksum(ip);
                udp->dgram_cksum = 0;
                udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
                m->ol_flags = 0; // no offloads
            }

            // Transmit echoed packet
            uint16_t sent = rte_eth_tx_burst(g_port_id, 0, &m, 1);
            tx_pkts += sent;
        }
    }

    std::printf("Stopping...\n");
    rte_eth_dev_stop(g_port_id);
    rte_eth_dev_close(g_port_id);
    return 0;
}
