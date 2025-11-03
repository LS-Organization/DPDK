#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <vector>
#include <algorithm>
#include <inttypes.h>

extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cycles.h>
}


static const char* get_opt(int argc, char** argv, const char* key, const char* defv){
  for (int i=0;i<argc-1;i++) if (!strcmp(argv[i], key)) return argv[i+1];
  return defv;
}
static bool has_flag(int argc, char** argv, const char* key){
  for (int i=0;i<argc;i++) if (!strcmp(argv[i], key)) return true;
  return false;
}


struct __attribute__((__packed__)) my_arp_ipv4 {
  uint16_t hrd;   // 1
  uint16_t pro;   // 0x0800
  uint8_t  hln;   // 6
  uint8_t  pln;   // 4
  uint16_t op;    // 1 req / 2 reply
  rte_ether_addr sha;
  uint32_t sip;
  rte_ether_addr tha;
  uint32_t tip;
};
static const uint16_t ARP_HRD_ETHER = 1;
static const uint16_t ARP_OP_REQUEST = 1;
static const uint16_t ARP_OP_REPLY   = 2;


struct __attribute__((__packed__)) rtt_payload {
  uint32_t magic;      // 0xC0FFEE01
  uint32_t seq;
  uint64_t tsc_send;
};
static const uint32_t RTT_MAGIC = 0xC0FFEE01;


static const uint16_t RX_RING_SIZE=1024, TX_RING_SIZE=1024, BURST=32;
static const unsigned  NUM_MBUFS=8192, MBUF_CACHE=250;

static volatile bool running=true;
static rte_mempool* mp=nullptr;
static uint16_t g_port=UINT16_MAX;

static void on_sig(int){ running=false; }


static inline uint32_t ipv4(const char* s){
  unsigned a,b,c,d; sscanf(s,"%u.%u.%u.%u",&a,&b,&c,&d);
  return rte_cpu_to_be_32((a<<24)|(b<<16)|(c<<8)|d);
}
static inline void mac_print(const char* t,const rte_ether_addr* a){
  printf("%s %02X:%02X:%02X:%02X:%02X:%02X",
    t,a->addr_bytes[0],a->addr_bytes[1],a->addr_bytes[2],
      a->addr_bytes[3],a->addr_bytes[4],a->addr_bytes[5]);
}

static bool handle_arp(rte_mbuf* m){
  auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
  if (rte_be_to_cpu_16(eth->ether_type)!=RTE_ETHER_TYPE_ARP) return false;
  auto* arp = (my_arp_ipv4*)(eth+1);
  if (rte_be_to_cpu_16(arp->hrd)!=ARP_HRD_ETHER) return false;
  if (rte_be_to_cpu_16(arp->pro)!=RTE_ETHER_TYPE_IPV4) return false;
  if (arp->hln!=RTE_ETHER_ADDR_LEN || arp->pln!=4) return false;
  if (rte_be_to_cpu_16(arp->op)!=ARP_OP_REQUEST) return false;

  rte_ether_addr mac; rte_eth_macaddr_get(g_port,&mac);
  eth->dst_addr = eth->src_addr;
  eth->src_addr = mac;

  arp->op  = rte_cpu_to_be_16(ARP_OP_REPLY);
  arp->tha = arp->sha;
  arp->tip = arp->sip;
  arp->sha = mac;

  rte_mbuf* one=m;
  if (rte_eth_tx_burst(g_port,0,&one,1)==0) rte_pktmbuf_free(m);
  return true;
}


static bool echo_udp(rte_mbuf* m){
  auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
  if (rte_be_to_cpu_16(eth->ether_type)!=RTE_ETHER_TYPE_IPV4) return false;
  auto* ip  = (rte_ipv4_hdr*)(eth+1);
  if (ip->next_proto_id!=IPPROTO_UDP) return false;
  uint8_t ihl = (ip->version_ihl & 0x0F)*4;
  auto* udp = (rte_udp_hdr*)((uint8_t*)ip + ihl);

  //  L2/L3/L4
  rte_ether_addr src = eth->src_addr, me; rte_eth_macaddr_get(g_port,&me);
  eth->src_addr = me; eth->dst_addr = src;
  uint32_t sip = ip->src_addr; ip->src_addr=ip->dst_addr; ip->dst_addr=sip;
  uint16_t sp = udp->src_port; udp->src_port=udp->dst_port; udp->dst_port=sp;

  ip->hdr_checksum=0; ip->hdr_checksum=rte_ipv4_cksum(ip);
  udp->dgram_cksum=0; udp->dgram_cksum=rte_ipv4_udptcp_cksum(ip,udp);

  rte_mbuf* one=m; if (rte_eth_tx_burst(g_port,0,&one,1)==0) rte_pktmbuf_free(m);
  return true;
}


static int port_init(uint16_t p){
  rte_eth_conf conf{};
  int ret=rte_eth_dev_configure(p,1,1,&conf); if(ret<0) return ret;
  uint16_t rx=RX_RING_SIZE, tx=TX_RING_SIZE;
  if((ret=rte_eth_dev_adjust_nb_rx_tx_desc(p,&rx,&tx))<0) return ret;
  if((ret=rte_eth_rx_queue_setup(p,0,rx,rte_eth_dev_socket_id(p),nullptr,mp))<0) return ret;
  if((ret=rte_eth_tx_queue_setup(p,0,tx,rte_eth_dev_socket_id(p),nullptr))<0) return ret;
  if((ret=rte_eth_dev_start(p))<0) return ret;

  rte_eth_promiscuous_enable(p);

  rte_ether_addr mac{}; rte_eth_macaddr_get(p,&mac);
  rte_eth_dev_info info{}; rte_eth_dev_info_get(p,&info);
  char name[64]={0}; rte_eth_dev_get_name_by_port(p,name);

  printf("Port %u started. name=%s  ", p,name);
  mac_print("MAC=",&mac);
  printf("  driver=%s\n", info.driver_name?info.driver_name:"(unknown)");
  return 0;
}

static int select_vdev_port_verbose() {
  uint16_t n = rte_eth_dev_count_avail();
  if (n==0) return -1;

  printf("=== ethdev inventory ===\n");
  for (uint16_t p=0;p<n;++p){
    rte_eth_dev_info info{}; rte_eth_dev_info_get(p,&info);
    char name[64]={0}; rte_eth_dev_get_name_by_port(p,name);
    printf("  port %u: name=%s driver=%s\n", p, name, info.driver_name?info.driver_name:"(unknown)");
  }

  auto match = [&](const char* key)->int{
    for (uint16_t p=0;p<n;++p){
      rte_eth_dev_info info{}; rte_eth_dev_info_get(p,&info);
      const char* drv = info.driver_name ? info.driver_name : "";
      char name[64]={0}; rte_eth_dev_get_name_by_port(p,name);
      if ((drv && strstr(drv,key)) || strstr(name,key)) return p;
    }
    return -1;
  };

  int p = match("net_af_packet");
  if (p>=0){ printf("Selected vdev (af_packet): port %d\n", p); return p; }

  p = match("net_tap");
  if (p>=0){ printf("Selected vdev (tap): port %d\n", p); return p; }

  
  for (uint16_t i=0;i<n;++i){
    char name[64]={0}; rte_eth_dev_get_name_by_port(i,name);
    if (!strncmp(name,"net_",4)) { printf("Selected vdev (generic): port %u\n", i); return (int)i; }
  }
  return -1;
}

static rte_mbuf* craft_udp_pkt(uint16_t payload_len,
                               uint32_t sip, uint32_t dip,
                               uint16_t sport, uint16_t dport,
                               const rte_ether_addr& src_mac,
                               const rte_ether_addr& dst_mac)
{
  const uint16_t L2=sizeof(rte_ether_hdr), L3=sizeof(rte_ipv4_hdr), L4=sizeof(rte_udp_hdr);
  uint16_t total = L2+L3+L4+payload_len;

  rte_mbuf* m = rte_pktmbuf_alloc(mp);
  if (!m) return nullptr;
  rte_pktmbuf_append(m,total);

  auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
  eth->src_addr = src_mac;
  eth->dst_addr = dst_mac;
  eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  auto* ip = (rte_ipv4_hdr*)((uint8_t*)eth + L2);
  memset(ip,0,sizeof(*ip));
  ip->version_ihl = (4<<4) | (sizeof(rte_ipv4_hdr)/4);
  ip->total_length = rte_cpu_to_be_16(L3+L4+payload_len);
  ip->time_to_live = 64;
  ip->next_proto_id = IPPROTO_UDP;
  ip->src_addr = sip;
  ip->dst_addr = dip;

  auto* udp = (rte_udp_hdr*)((uint8_t*)ip + L3);
  udp->src_port = rte_cpu_to_be_16(sport);
  udp->dst_port = rte_cpu_to_be_16(dport);
  udp->dgram_len = rte_cpu_to_be_16(L4+payload_len);

  ip->hdr_checksum = rte_ipv4_cksum(ip);
  udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);
  return m;
}

/* =============================== main =============================== */
int main(int argc, char** argv){
  signal(SIGINT,on_sig); signal(SIGTERM,on_sig);

  /* EAL init */
  int ealret = rte_eal_init(argc, argv);
  if (ealret<0) rte_exit(EXIT_FAILURE,"EAL init failed\n");
  int app_argc = argc - ealret; char** app_argv = argv + ealret;

 
  const char* mode   = get_opt(app_argc, app_argv, "--mode", "txrx"); // echo / txrx
  const char* sip_s  = get_opt(app_argc, app_argv, "--src-ip", "10.10.0.2");
  const char* dip_s  = get_opt(app_argc, app_argv, "--dst-ip", "10.10.0.3");
  uint32_t sip = ipv4(sip_s), dip = ipv4(dip_s);
  uint16_t sport = (uint16_t)atoi(get_opt(app_argc, app_argv, "--sport", "12345"));
  uint16_t dport = (uint16_t)atoi(get_opt(app_argc, app_argv, "--dport", "9000"));
  uint32_t pps   = (uint32_t)atoi(get_opt(app_argc, app_argv, "--pps", "100000"));   // 100kpps
  uint16_t paylen= (uint16_t)atoi(get_opt(app_argc, app_argv, "--payload-len", "32"));
  double   seconds= atof(get_opt(app_argc, app_argv, "--seconds", "0")); 
  const char* dst_mac_s = get_opt(app_argc, app_argv, "--dst-mac", "ff:ff:ff:ff:ff:ff"); 
  rte_ether_addr dst_mac{};
  if (sscanf(dst_mac_s,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
      &dst_mac.addr_bytes[0],&dst_mac.addr_bytes[1],&dst_mac.addr_bytes[2],
      &dst_mac.addr_bytes[3],&dst_mac.addr_bytes[4],&dst_mac.addr_bytes[5])!=6) {
    for(int i=0;i<6;i++) dst_mac.addr_bytes[i]=0xFF;
  }

  /* mempool */
  mp = rte_pktmbuf_pool_create("MBUF", NUM_MBUFS, MBUF_CACHE, 0,
                               RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (!mp) rte_exit(EXIT_FAILURE,"mempool create failed\n");


  int sel = select_vdev_port_verbose();
  if (sel<0) {
    rte_exit(EXIT_FAILURE,
      "No vdev port found. \n");
  }
  g_port = (uint16_t)sel;
  if (port_init(g_port)<0) rte_exit(EXIT_FAILURE,"port init failed\n");

  printf("Mode=%s  src=%s:%u  dst=%s:%u  pps=%u payload=%uB dst-mac=%s\n",
         mode,sip_s,sport,dip_s,dport,pps,paylen,dst_mac_s);

  if (!strcmp(mode,"echo")){
    printf("Echo loop ... Ctrl+C to stop\n");
    while(running){
      rte_mbuf* bufs[ BURST ];
      uint16_t n = rte_eth_rx_burst(g_port,0,bufs,BURST);
      for(uint16_t i=0;i<n;++i){
        rte_mbuf* m=bufs[i];
        if (!handle_arp(m)) {
          if (!echo_udp(m)) rte_pktmbuf_free(m);
        }
      }
    }
    rte_eth_dev_stop(g_port); rte_eal_cleanup(); return 0;
  }

  /* --------- txrx (RTT) --------- */
  rte_ether_addr mymac; rte_eth_macaddr_get(g_port,&mymac);

  // payload= rtt_payload + user pad
  uint16_t full_payload = (uint16_t)(sizeof(rtt_payload) + paylen);
  rte_mbuf* tmpl = craft_udp_pkt(full_payload, sip, dip, sport, dport, mymac, dst_mac);
  if (!tmpl) rte_exit(EXIT_FAILURE,"craft pkt failed\n");

  uint8_t* l2 = rte_pktmbuf_mtod(tmpl, uint8_t*);
  auto* ip  = (rte_ipv4_hdr*)(l2 + sizeof(rte_ether_hdr));
  auto* udp = (rte_udp_hdr*)((uint8_t*)ip + sizeof(rte_ipv4_hdr));
  auto* pl  = (rtt_payload*)((uint8_t*)udp + sizeof(rte_udp_hdr));
  uint8_t* user_pad = (uint8_t*)(pl+1);

  uint64_t hz = rte_get_tsc_hz();
  uint64_t last_stat = rte_get_tsc_cycles();
  uint64_t deadline = (seconds>0)? last_stat + (uint64_t)(seconds*hz) : 0;
  uint32_t seq=0;
  uint64_t tx_pkts=0, rx_pkts=0;
  std::vector<double> rtts_us; rtts_us.reserve(1<<20);

  // 
  const double interval = (pps>0)? (hz / (double)pps) : 0.0;
  double next_send = (double)rte_get_tsc_cycles();

  printf("RTT test running ... Ctrl+C to stop\n");
  while(running){
    uint64_t now = rte_get_tsc_cycles();
    if (seconds>0 && now>=deadline) break;

    // pace send
    if (interval==0 || now >= (uint64_t)next_send){
      pl->magic = rte_cpu_to_be_32(RTT_MAGIC);
      pl->seq   = rte_cpu_to_be_32(seq++);
      pl->tsc_send = rte_cpu_to_be_64(rte_get_tsc_cycles());
      if (paylen) memset(user_pad, 0xAB, paylen);

      ip->hdr_checksum=0; ip->hdr_checksum=rte_ipv4_cksum(ip);
      udp->dgram_cksum=0; udp->dgram_cksum=rte_ipv4_udptcp_cksum(ip,udp);

      rte_mbuf* m = rte_pktmbuf_clone(tmpl, mp);
      if (m){
        rte_mbuf* one=m;
        if (rte_eth_tx_burst(g_port,0,&one,1)==0) rte_pktmbuf_free(m);
        else tx_pkts++;
      }
      next_send += interval;
    }

    // RX
    rte_mbuf* bufs[BURST];
    uint16_t n = rte_eth_rx_burst(g_port,0,bufs,BURST);
    for(uint16_t i=0;i<n;++i){
      rte_mbuf* m = bufs[i];
      auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
      if (rte_be_to_cpu_16(eth->ether_type)==RTE_ETHER_TYPE_IPV4){
        auto* ipr = (rte_ipv4_hdr*)(eth+1);
        if (ipr->next_proto_id==IPPROTO_UDP){
          auto* udpr = (rte_udp_hdr*)((uint8_t*)ipr + sizeof(rte_ipv4_hdr));
          auto* plr  = (rtt_payload*)((uint8_t*)udpr + sizeof(rte_udp_hdr));
          if (rte_be_to_cpu_32(plr->magic)==RTT_MAGIC){
            uint64_t tsc_send = rte_be_to_cpu_64(plr->tsc_send);
            double us = (double)(rte_get_tsc_cycles() - tsc_send) * 1e6 / hz;
            rtts_us.push_back(us);
            rx_pkts++;
          }
        }
      }
      rte_pktmbuf_free(m);
    }

    // 
    if (now - last_stat > hz){
      double loss = (tx_pkts>0)? (100.0 * (tx_pkts - rx_pkts) / tx_pkts) : 0.0;

      double p50=0,p95=0,p99=0,avg=0,minv=0,maxv=0;
      if (!rtts_us.empty()){
        std::sort(rtts_us.begin(), rtts_us.end());
        minv = rtts_us.front(); maxv = rtts_us.back();
        size_t nrt = rtts_us.size();
        p50 = rtts_us[nrt*50/100];
        p95 = rtts_us[nrt*95/100];
        p99 = rtts_us[nrt*99/100];
        double sum=0; for(double v: rtts_us) sum+=v; avg = sum/nrt;
      }

      printf("[RTT] sent=%" PRIu64 " recv=%" PRIu64 " loss=%.2f%%  "
             "TX=%.3f Mpps  RX=%.3f Mpps\n",
             tx_pkts, rx_pkts, loss, tx_pkts/1e6, rx_pkts/1e6);
      if (!rtts_us.empty()){
        printf("      rtt(us): min=%.2f avg=%.2f p50=%.2f p95=%.2f p99=%.2f max=%.2f (samples=%zu)\n",
               minv, avg, p50, p95, p99, maxv, rtts_us.size());
      } else {
        printf("      rtt(us): (no samples yet)\n");
      }
      rtts_us.clear();
      tx_pkts=rx_pkts=0;
      last_stat = now;
    }
  }

  rte_eth_dev_stop(g_port);
  rte_eal_cleanup();
  return 0;
}
