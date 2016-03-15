#ifndef ODINAGENT_H
#define ODINAGENT_H

#include "utils/includes.h"
#include <pthread.h>
#include <time.h>
#include <strings.h>
#ifndef CONFIG_NATIVE_WINDOWS
#include <syslog.h>
#include <grp.h>
#endif /* CONFIG_NATIVE_WINDOWS */

#include "utils/eloop.h"
#include "utils/common.h"
#include "tstl2cl/include/c_def.h"
#include "tstl2cl/include/c_vector.h"
#include "tstl2cl/include/c_map.h"
#include "ap/hostapd.h"

#define CONTROLLER 			"192.168.0.99"
#define TCP_LISTEN_PORT     6777
#define UDP_DEST_PORT       2819
#define MAX_QUE_CONN_NM     5
#define MAX_SOCK_FD         FD_SETSIZE
#define BUFFER_SIZE         1024
#define PROTOCOL_TYPE_NUM	15
#define IP_ALEN				4
#define STRING_MAX_LEN		50
#define SSID_MAX_LEN		50
#define SIGNAL_OFFSET		256
#define OVS_BRIDGE_NAME		"br1"
#define RADIOTAP_HEADER_LEN 13

#ifndef IP2STR
#define IP2STR(a) a[0], a[1], a[2], a[3]
#define IPSTR	"%d.%d.%d.%d"
#endif

struct swan_config {
    u8 controller_ip[IP_ALEN];
    int tcp_listen_port;
    int udp_dest_port;
};

static inline void str2ip(const char *str, u8 *ip)
{
	int i;
	const char *p = str;
	for (i = 0; i < IP_ALEN; i++) {
	  ip[i] = atoi(p);
	  p = strchr(p, '.');
	  p++;
	}
}

/*convert a string to a macaddress data type.*/
#define COPY_STR2MAC(str, mac)  \
do { \
    hwaddr_aton(str, mac);\
} while(0)
/*convert a string to a ip data type.*/
#define COPY_STR2IP(str, ip)  \
do { \
	str2ip(str, ip);\
} while(0)

typedef struct EtherAddress {
	unsigned char mac_addr[ETH_ALEN];
}EtherAddress;

typedef struct IPAddress {
	unsigned char ip[IP_ALEN];
}IPAddress;

typedef struct String {
	unsigned char length;
	unsigned char str[0];
}String;

typedef enum relation_t {
    EQUALS = 0,
    GREATER_THAN = 1,
    LESSER_THAN = 2,
}relation_t;

typedef struct OdinStationState {
	EtherAddress _vap_bssid;
	IPAddress _sta_ip_addr_v4;
	//Vector<String> _vap_ssids;
	//c_pvector _vap_ssids;
	String _vap_ssids;// FIXME
}OdinStationState;

typedef struct Subscription {
    long subscription_id;
    enum relation_t rel;
    double val;
    EtherAddress sta_addr;
    unsigned char reserved[1];// 用于字节对齐
    String statistic;
}Subscription;

// Rx-stats about stations
typedef struct StationStats {
  int _rate;
  int _noise;
  int _signal;
  int _packets;
  time_t _last_received;//以秒为单位的日历时间(即从1970年1月1日0时0分0秒到现在的秒数)
}StationStats;

// All VAP related information should be accessible here on
// a per client basis
//HashTable<EtherAddress, OdinStationState> _sta_mapping_table;
c_pmap _sta_mapping_table;
c_pmap _mean_table;

// Keep track of rx-statistics of stations from which
// we hear frames. Only keeping track of data frames for
// now.
//HashTable<EtherAddress, StationStats> _rx_stats;
c_pmap _rx_stats;

c_pvector _subscription_list;

typedef enum protocol_type {
    handler_view_mapping_table,
    handler_channel,
    handler_interval,
    handler_rxstat,
    handler_subscriptions,
    handler_debug,
    handler_report_mean,
    handler_spectral_scan,
    handler_add_vap,
    handler_set_vap,
    handler_remove_vap,
    handler_probe_response,
    handler_probe_request,
    handler_update_signal_strength,
    handler_signal_strength_offset,
}protocol_type;

extern char *protocol_string[15];

//global thread id
pthread_t odin_thread_id;
pthread_t cleanup_thread_id;
pthread_t beacon_thread_id;
int server_sockfd, odin_udp_sockfd;
c_pvector client_sock_vector;

// global hapd_interfaces
struct hapd_interfaces *interfaces;
struct swan_config *swan_conf;

/* odinagent.c */
void odin_protocol_init();
void odin_protocol_deinit();
int odin_send_msg(protocol_type type);
void odin_protocol_handler(int sock, void *eloop_ctx, void *sock_ctx);
void odin_handle_monitor_read(int sock, void *eloop_ctx, void *sock_ctx);

#endif /* ODINAGENT_H */
