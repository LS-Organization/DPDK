
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

extern "C" {
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cycles.h>
}

using std::printf; using std::size_t;

constexpr uint16_t RX_RING_SIZE = 1024;
constexpr uint16_t TX_RING_SIZE = 512;  // ENA <=512
constexpr uint32_t NUM_MBUFS    = 8192;
constexpr uint32_t MBUF_CACHE   = 250;
constexpr uint16_t BURST_SIZE   = 64;

#pragma pack(push,1)
struct MsgHdr {
    uint32_t magic;      // 0xC0DEBEEF
    uint16_t hdr_len;    // sizeof(MsgHdr)
    uint16_t pay_len;    // payload length (not include header)
    uint64_t seq;
    uint64_t send_ts_ns;
    uint64_t pay_hash;   // FNV-1a of payload
};
#pragma pack(pop)

static constexpr uint32_t MAGIC = 0xC0DEBEEF;

static inline uint64_t fnv1a64(const void* data, size_t len){
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ULL; const uint64_t prime = 1099511628211ULL;
    for (size_t i=0;i<len;i++){ h ^= p[i]; h *= prime; }
    return h;
}

static inline uint16_t ip_checksum(const void* vdata, size_t len){
    const uint16_t* data = static_cast<const uint16_t*>(vdata); uint32_t acc=0;
    for (size_t i=0;i<len/2;i++) acc += data[i];
    while (acc>>16) acc = (acc & 0xFFFF) + (acc>>16);
    return static_cast<uint16_t>(~acc);
}

static inline uint16_t udp_checksum_ipv4(const rte_ipv4_hdr* ip, const rte_udp_hdr* udp,
                                         const uint8_t* payload, size_t payload_len){
    uint32_t sum=0;
    auto be16 = [](uint32_t v){ return static_cast<uint16_t>((v)&0xFFFF); };
    sum += be16(rte_be_to_cpu_32(ip->src_addr) >> 16);
    sum += be16(rte_be_to_cpu_32(ip->src_addr));
    sum += be16(rte_be_to_cpu_32(ip->dst_addr) >> 16);
    sum += be16(rte_be_to_cpu_32(ip->dst_addr));
    sum += IPPROTO_UDP;
    sum += rte_be_to_cpu_16(udp->dgram_len);

    const uint16_t* u = reinterpret_cast<const uint16_t*>(udp);
    for (size_t i=0;i<sizeof(*udp)/2;i++) sum += rte_be_to_cpu_16(u[i]);

    const uint16_t* p = reinterpret_cast<const uint16_t*>(payload);
    size_t words = payload_len/2;
    for (size_t i=0;i<words;i++) sum += rte_be_to_cpu_16(p[i]);
    if (payload_len & 1) sum += static_cast<uint16_t>(payload[payload_len-1]) << 8;

    while (sum>>16) sum = (sum & 0xFFFF) + (sum>>16);
    return static_cast<uint16_t>(~sum);
}

struct AppCfg { uint16_t portid=0; uint8_t drop_only=0; uint16_t rxq=1, txq=1; } cfg;

static void parse_app_args(int argc, char** argv){
    for (int i=1;i<argc;i++){
        if (!std::strcmp(argv[i], "--drop") && i+1<argc) cfg.drop_only=(uint8_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--rxq") && i+1<argc) cfg.rxq=(uint16_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--txq") && i+1<argc) cfg.txq=(uint16_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--portid") && i+1<argc) cfg.portid=(uint16_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "-p") && i+1<argc) { ++i; /* ignore mask for simplicity */ }
    }
}

static int port_init(uint16_t port, rte_mempool* pool){
    const uint16_t rx_rings = 1, tx_rings = 1;
    rte_eth_conf conf{}; conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;  
    conf.rx_adv_conf.rss_conf.rss_hf = 0;  

    int ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &conf);
    if (ret < 0) return ret;
    for (uint16_t q=0;q<rx_rings;q++){
        ret = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), nullptr, pool);
        if (ret < 0) return ret;
    }
    for (uint16_t q=0;q<tx_rings;q++){
        ret = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), nullptr);
        if (ret < 0) return ret;
    }
    ret = rte_eth_dev_start(port); if (ret<0) return ret;
    rte_eth_promiscuous_enable(port);
    return 0;
}

struct Stat { uint64_t rx=0, tx=0, ok=0, bad_magic=0, bad_len=0, bad_hash=0; } gstat;

static inline void swap_eth(rte_ether_hdr* eth){ auto tmp=eth->src_addr; eth->src_addr=eth->dst_addr; eth->dst_addr=tmp; }
static inline void swap_ip_ports(rte_ipv4_hdr* ip, rte_udp_hdr* udp){ auto tmp_ip=ip->src_addr; ip->src_addr=ip->dst_addr; ip->dst_addr=tmp_ip; auto tmp_p=udp->src_port; udp->src_port=udp->dst_port; udp->dst_port=tmp_p; }

static int lcore_main(void*){
    const uint16_t port = cfg.portid; const uint64_t hz = rte_get_timer_hz();
    uint64_t last_tsc = rte_get_timer_cycles(); uint64_t last_rx = 0;

    for(;;){
        rte_mbuf* pkts[BURST_SIZE];
        uint16_t nb = rte_eth_rx_burst(port, 0, pkts, BURST_SIZE);
        if (nb==0){
            uint64_t now = rte_get_timer_cycles();
            if (now - last_tsc > hz){
                double secs = double(now - last_tsc)/hz; uint64_t d = gstat.rx - last_rx;
                double inst = double(d)/secs/1e6; double avg = double(gstat.rx)/ (double(now)/hz) /1e6;
                printf("[dpdk] +%.2fs inst=%.3f Mpps avg=%.3f Mpps RX=%lu TX=%lu ok=%lu bad=%lu/%lu\n",
                    secs, inst, avg, gstat.rx, gstat.tx, gstat.ok, gstat.bad_len, gstat.bad_hash);
                fflush(stdout); last_tsc = now; last_rx = gstat.rx;
            }
            continue;
        }
        for (uint16_t i=0;i<nb;i++){
            rte_mbuf* m = pkts[i]; gstat.rx++;
            uint8_t* data = rte_pktmbuf_mtod(m, uint8_t*); size_t len = rte_pktmbuf_data_len(m);
            if (len < sizeof(rte_ether_hdr)+sizeof(rte_ipv4_hdr)+sizeof(rte_udp_hdr)+sizeof(MsgHdr)) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            auto* eth = reinterpret_cast<rte_ether_hdr*>(data);
            if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            auto* ip = reinterpret_cast<rte_ipv4_hdr*>(eth+1);
            if (ip->next_proto_id != IPPROTO_UDP) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            auto* udp = reinterpret_cast<rte_udp_hdr*>(ip+1);
            uint16_t ulen = rte_be_to_cpu_16(udp->dgram_len);
            uint16_t iphdr_len = (ip->version_ihl & 0x0F) * 4;
            if (ulen < sizeof(rte_udp_hdr)+sizeof(MsgHdr)) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            uint8_t* payload = reinterpret_cast<uint8_t*>(udp) + sizeof(rte_udp_hdr);
            size_t payload_len = size_t(ulen) - sizeof(rte_udp_hdr);
            auto* mh = reinterpret_cast<MsgHdr*>(payload);
          
            if (mh->magic != MAGIC && mh->magic != rte_cpu_to_le_32(MAGIC)) { gstat.bad_magic++; rte_pktmbuf_free(m); continue; }
            if (mh->hdr_len != sizeof(MsgHdr)) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            if (size_t(mh->hdr_len) + mh->pay_len != payload_len) { gstat.bad_len++; rte_pktmbuf_free(m); continue; }
            auto* pay = reinterpret_cast<uint8_t*>(mh) + mh->hdr_len;
            uint64_t h = fnv1a64(pay, mh->pay_len);
            if (h != mh->pay_hash) { gstat.bad_hash++; if (cfg.drop_only){ rte_pktmbuf_free(m); continue; } }
            else gstat.ok++;

            if (cfg.drop_only){ rte_pktmbuf_free(m); continue; }
         
            std::memset(pay, 0x02, mh->pay_len);
            mh->pay_hash = fnv1a64(pay, mh->pay_len);
           
            swap_eth(eth); swap_ip_ports(ip, udp);
          
            ip->hdr_checksum = 0; ip->hdr_checksum = ip_checksum(ip, iphdr_len);
            udp->dgram_cksum = 0; udp->dgram_cksum = udp_checksum_ipv4(ip, udp, reinterpret_cast<uint8_t*>(mh), payload_len);
            uint16_t sent = rte_eth_tx_burst(port, 0, &m, 1);
            if (!sent) rte_pktmbuf_free(m); else gstat.tx += sent;
        }
        uint64_t now = rte_get_timer_cycles();
        if (now - last_tsc > rte_get_timer_hz()){
            double secs = double(now - last_tsc)/rte_get_timer_hz(); uint64_t d = gstat.rx - last_rx;
            double inst = double(d)/secs/1e6; double avg = double(gstat.rx)/ (double(now)/rte_get_timer_hz()) /1e6;
            printf("[dpdk] +%.2fs inst=%.3f Mpps avg=%.3f Mpps RX=%lu TX=%lu ok=%lu bad=%lu/%lu\n",
                secs, inst, avg, gstat.rx, gstat.tx, gstat.ok, gstat.bad_len, gstat.bad_hash);
            fflush(stdout); last_tsc = now; last_rx = gstat.rx;
        }
    }
}

int main(int argc, char** argv){
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    int app_argc = argc - ret; char** app_argv = argv + ret; (void)app_argc; parse_app_args(app_argc, app_argv);

    uint16_t port = cfg.portid;
    if (!rte_eth_dev_is_valid_port(port)) rte_exit(EXIT_FAILURE, "Invalid port %u\n", port);

    rte_mempool* pool = rte_pktmbuf_pool_create("MBUF", NUM_MBUFS, MBUF_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    if (port_init(port, pool) != 0) rte_exit(EXIT_FAILURE, "port init failed\n");

    printf("dpdk_udp (C++) starting: port=%u drop=%u rxq=%u txq=%u\n", port, cfg.drop_only, cfg.rxq, cfg.txq);
    return lcore_main(nullptr);
}
