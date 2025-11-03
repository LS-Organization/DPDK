#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <inttypes.h>

extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cycles.h>
}

/*** Minimal ARP (IPv4) header (packed) ***/
struct __attribute__((__packed__)) my_arp_ipv4 {
    uint16_t hrd;   // 1 = Ethernet
    uint16_t pro;   // 0x0800 = IPv4
    uint8_t  hln;   // 6
    uint8_t  pln;   // 4
    uint16_t op;    // 1=request, 2=reply
    struct rte_ether_addr sha; // sender MAC
    uint32_t sip;   // sender IP (BE)
    struct rte_ether_addr tha; // target MAC
    uint32_t tip;   // target IP (BE)
};
static const uint16_t ARP_HRD_ETHER = 1;
static const uint16_t ARP_OP_REQUEST = 1;
static const uint16_t ARP_OP_REPLY   = 2;

/*** App config ***/
static const uint16_t RX_RING_SIZE = 1024;
static const uint16_t TX_RING_SIZE = 1024;
static const uint16_t BURST_SIZE   = 32;
static const unsigned  NUM_MBUFS   = 8192;
static const unsigned  MBUF_CACHE  = 250;

static volatile bool running = true;
static rte_mempool* mbuf_pool = nullptr;
static uint16_t g_port = UINT16_MAX;

static void on_sig(int){ running = false; }

static inline void print_mac(const char* title, const rte_ether_addr* a) {
    printf("%s %02X:%02X:%02X:%02X:%02X:%02X",
           title, a->addr_bytes[0], a->addr_bytes[1], a->addr_bytes[2],
           a->addr_bytes[3], a->addr_bytes[4], a->addr_bytes[5]);
}
static inline void print_ipv4(uint32_t be_ip) {
    uint32_t ip = rte_be_to_cpu_32(be_ip);
    printf("%u.%u.%u.%u", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
}

/*** ARP reply ***/
static bool handle_arp(struct rte_mbuf* m) {
    auto* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
    if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_ARP) return false;

    auto* arp = (struct my_arp_ipv4*)(eth + 1);
    if (rte_be_to_cpu_16(arp->hrd) != ARP_HRD_ETHER) return false;
    if (rte_be_to_cpu_16(arp->pro) != RTE_ETHER_TYPE_IPV4) return false;
    if (arp->hln != RTE_ETHER_ADDR_LEN || arp->pln != 4) return false;

    if (rte_be_to_cpu_16(arp->op) != ARP_OP_REQUEST) {
        print_mac("[ARP]  dst=", &eth->dst_addr); printf(" ");
        print_mac("src=", &eth->src_addr); printf(" len=%u\n", m->pkt_len);
        return false;
    }

    uint32_t requested_ip = arp->tip;

    struct rte_ether_addr mymac;
    rte_eth_macaddr_get(g_port, &mymac);

    eth->dst_addr = eth->src_addr;
    eth->src_addr = mymac;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    arp->op  = rte_cpu_to_be_16(ARP_OP_REPLY);
    arp->tha = arp->sha;
    arp->tip = arp->sip;
    arp->sha = mymac;
    arp->sip = requested_ip;

    struct rte_mbuf* one = m;
    uint16_t sent = rte_eth_tx_burst(g_port, 0, &one, 1);
    if (sent == 0) rte_pktmbuf_free(m);

    printf("[ARP-REPLY] "); print_mac("to=", &eth->dst_addr);
    printf(" sip="); print_ipv4(arp->sip); printf("\n");
    return true;
}

/*** IPv4/UDP echo ***/
static bool handle_ipv4_udp_echo(struct rte_mbuf* m) {
    auto* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
    auto* ip  = (struct rte_ipv4_hdr*)(eth + 1);

    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(*ip)) return false;
    if (ip->next_proto_id != IPPROTO_UDP) return false;

    auto* udp = (struct rte_udp_hdr*)((uint8_t*)ip + ihl);

    printf("[IPv4/UDP RX] ");
    print_ipv4(ip->src_addr); printf(":%u -> ",
        (unsigned)rte_be_to_cpu_16(udp->src_port));
    print_ipv4(ip->dst_addr); printf(":%u len=%u\n",
        (unsigned)rte_be_to_cpu_16(udp->dst_port), m->pkt_len);

    struct rte_ether_addr src_mac = eth->src_addr;
    struct rte_ether_addr mymac; rte_eth_macaddr_get(g_port, &mymac);
    eth->src_addr = mymac;
    eth->dst_addr = src_mac;

    uint32_t src_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = src_ip;

    uint16_t sp = udp->src_port;
    udp->src_port = udp->dst_port;
    udp->dst_port = sp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, (const void*)udp);

    struct rte_mbuf* one = m;
    uint16_t sent = rte_eth_tx_burst(g_port, 0, &one, 1);
    if (sent == 0) { rte_pktmbuf_free(m); return true; }

    printf("[UDP-ECHO TX] ");
    print_ipv4(ip->src_addr); printf(":%u -> ",
        (unsigned)rte_be_to_cpu_16(udp->src_port));
    print_ipv4(ip->dst_addr); printf(":%u len=%u\n",
        (unsigned)rte_be_to_cpu_16(udp->dst_port), m->pkt_len);
    printf("\n");
    return true;
}

/*** port init ***/
static int port_init(uint16_t port, rte_mempool* mp) {
    if (!rte_eth_dev_is_valid_port(port)) return -1;

    rte_eth_conf conf{};
    int ret = rte_eth_dev_configure(port, 1, 1, &conf);
    if (ret < 0) return ret;

    uint16_t nb_rx = RX_RING_SIZE, nb_tx = TX_RING_SIZE;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx)) < 0) return ret;
    if ((ret = rte_eth_rx_queue_setup(port, 0, nb_rx, rte_eth_dev_socket_id(port), nullptr, mp)) < 0) return ret;
    if ((ret = rte_eth_tx_queue_setup(port, 0, nb_tx, rte_eth_dev_socket_id(port), nullptr)) < 0) return ret;

    if ((ret = rte_eth_dev_start(port)) < 0) return ret;

    rte_eth_promiscuous_enable(port);

    rte_ether_addr mac{}; rte_eth_macaddr_get(port, &mac);
    rte_eth_dev_info info{}; rte_eth_dev_info_get(port, &info);
    char name[64] = {0}; rte_eth_dev_get_name_by_port(port, name);

    printf("Port %u started. name=%s  ", port, name);
    print_mac("MAC=", &mac);
    printf("  driver=%s\n", info.driver_name ? info.driver_name : "(unknown)");

    return 0;
}

/*** choose vdev port ***/
static int select_vdev_port() {
    uint16_t n = rte_eth_dev_count_avail();
    if (n == 0) return -1;

    // 1) 优先 net_af_packet
    for (uint16_t p = 0; p < n; ++p) {
        rte_eth_dev_info info{};
        rte_eth_dev_info_get(p, &info);
        const char* drv = info.driver_name ? info.driver_name : "";
        if (strstr(drv, "net_af_packet")) return (int)p;
        char name[64] = {0};
        rte_eth_dev_get_name_by_port(p, name);
        if (strstr(name, "net_af_packet")) return (int)p;
    }
    // 2) 其次任何名字以 net_ 开头的 vdev（如 net_tap）
    for (uint16_t p = 0; p < n; ++p) {
        char name[64] = {0};
        rte_eth_dev_get_name_by_port(p, name);
        if (strncmp(name, "net_", 4) == 0) return (int)p;
    }
    return -1;
}

/*** main ***/
int main(int argc, char** argv) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                    NUM_MBUFS, MBUF_CACHE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "mempool create failed\n");

    int sel = select_vdev_port();
    if (sel < 0) {
        // 友好提示
        uint16_t n = rte_eth_dev_count_avail();
        fprintf(stderr, "No vdev port found. ethdevs=%u\n", n);
        for (uint16_t p = 0; p < n; ++p) {
            rte_eth_dev_info info{}; rte_eth_dev_info_get(p, &info);
            char name[64] = {0}; rte_eth_dev_get_name_by_port(p, name);
            fprintf(stderr, "  port %u: name=%s driver=%s\n",
                    p, name, info.driver_name ? info.driver_name : "(unknown)");
        }
        rte_exit(EXIT_FAILURE, "Run with --no-pci and/or --vdev=net_af_packet0,iface=...\n");
    }

    g_port = (uint16_t)sel;
    if (port_init(g_port, mbuf_pool) < 0) rte_exit(EXIT_FAILURE, "port init failed\n");

    printf("Echo loop running on port %u ... Ctrl+C to stop.\n", g_port);

    uint64_t last = rte_get_tsc_cycles(), hz = rte_get_tsc_hz();
    uint64_t rx_prev=0, tx_prev=0;

    while (running) {
        rte_mbuf* bufs[BURST_SIZE];
        uint16_t n = rte_eth_rx_burst(g_port, 0, bufs, BURST_SIZE);

        if (n == 0) {
            uint64_t now = rte_get_tsc_cycles();
            if (now - last > hz) {
                struct rte_eth_stats st{};
                if (rte_eth_stats_get(g_port, &st) == 0) {
                    printf("[STATS] RX=%" PRIu64 " TX=%" PRIu64 " (delta rx=%" PRIu64 " tx=%" PRIu64 ")\n",
                           st.ipackets, st.opackets,
                           st.ipackets - rx_prev, st.opackets - tx_prev);
                    rx_prev = st.ipackets; tx_prev = st.opackets;
                }
                last = now;
            }
            rte_delay_us_block(50);
            continue;
        }

        printf("Got %u packets\n", n);

        for (uint16_t i = 0; i < n; ++i) {
            rte_mbuf* m = bufs[i];
            auto* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
            uint16_t et = rte_be_to_cpu_16(eth->ether_type);

            bool consumed = false;
            if (et == RTE_ETHER_TYPE_ARP) {
                consumed = handle_arp(m);
            } else if (et == RTE_ETHER_TYPE_IPV4) {
                auto* ip = (struct rte_ipv4_hdr*)(eth + 1);
                if (ip->next_proto_id == IPPROTO_UDP)
                    consumed = handle_ipv4_udp_echo(m);
            }

            if (!consumed) {
                // 简单打印并释放
                if (et == RTE_ETHER_TYPE_IPV4) {
                    auto* ip = (struct rte_ipv4_hdr*)(eth + 1);
                    printf("[IPv4/%u] ", ip->next_proto_id);
                    print_ipv4(ip->src_addr); printf(" -> "); print_ipv4(ip->dst_addr);
                    printf(" len=%u\n", m->pkt_len);
                } else if (et == RTE_ETHER_TYPE_ARP) {
                    print_mac("[ARP] dst=", &eth->dst_addr); printf(" ");
                    print_mac("src=", &eth->src_addr); printf(" len=%u\n", m->pkt_len);
                } else {
                    printf("[ETH 0x%04x] len=%u\n", et, m->pkt_len);
                }
                rte_pktmbuf_free(m);
            }
        }
    }

    printf("Stopping...\n");
    rte_eth_dev_stop(g_port);
    rte_eal_cleanup();
    return 0;
}
