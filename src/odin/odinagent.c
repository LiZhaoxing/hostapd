#include <pthread.h>
#include <sys/time.h>
#include <signal.h>

#include "odin/odinagent.h"
#include "utils/wpa_debug.h"
#include "utils/radiotap.h"
#include "utils/radiotap_iter.h"
#include "drivers/driver.h"
#include "common/ieee802_11_defs.h"
#include "ap/ieee802_11.h"
#include "ap/sta_info.h"

void remove_odin_lvaps_all();
void send_beacon(EtherAddress dst, EtherAddress bssid, String *my_ssid);
struct swan_config * swan_config_read(const char *fname);

char *protocol_string[15] = {"table", "channel", "interval", "rxstats",
						  "subscriptions", "debug", "report_mean", "spectral_scan",
						  "add_vap", "set_vap", "remove_vap", "send_probe_response",
						  "testing_send_probe_request", "handler_update_signal_strength",
						  "signal_strength_offset"};

static inline int string_comparer(void *x, void *y)
{
	unsigned char length = (((String *)(x))->length) > (((String *)(y))->length) ? (((String *)(y))->length) : (((String *)(x))->length);
	int i;

	for (i = 0; i < length; i++)
	{
		if ( ( ((String *)(x))->str[i] - ((String *)(y))->str[i] ) == 0 ) {
			continue;
		}
		else {
			return ((String *)(x))->str[i] - ((String *)(y))->str[i];
		}
	}
    return 0;
}

static inline int subscription_comparer(void * x, void * y)
{
	return ((Subscription *)(x))->subscription_id - ((Subscription *)(y))->subscription_id;
}

static inline int etheraddress_comparer(void * x, void * y)
{
	int i;
    for (i = 0; i < ETH_ALEN; i++) {
    	if ( ( ((EtherAddress *)(x))->mac_addr[i] - ((EtherAddress *)(y))->mac_addr[i]) == 0 ) {
    		continue;
    	}
    	else {
    		return ((EtherAddress *)(x))->mac_addr[i] - ((EtherAddress *)(y))->mac_addr[i];
    	}
    }
    return 0;
}

static inline int int_comparer(void * x, void * y)
{
    return *(int *)(x) - *(int *)(y);
}

void free_map(c_pmap thiz)
{
	c_iterator iter = c_map_begin(thiz);
	c_iterator end = c_map_end(thiz);

	for(; !ITER_EQUAL(iter, end); ITER_INC(iter))
	{
		free(((c_ppair)ITER_REF(iter))->first);
		free(((c_ppair)ITER_REF(iter))->second);
		((c_ppair)ITER_REF(iter))->first = NULL;
		((c_ppair)ITER_REF(iter))->second = NULL;
		free(ITER_REF(iter));
		c_map_erase(thiz, iter);
	}
	return;
}

void map_init(c_pmap *map, int (*comparer_function)(void *, void *))
{
	*map = (c_pmap)malloc(sizeof(c_map));
	if(*map == NULL) {
		wpa_printf(MSG_INFO, "malloc map error......");
	}
	c_map_create(*map, comparer_function);
}

void map_deinit(c_pmap *map)
{
	free_map(*map);
	//c_map_clear(_sta_mapping_table);
	//c_map_clear(_rx_stats);
	c_map_destroy(*map);
}

void free_vector(c_pvector p)
{
	c_iterator iter;
	c_iterator first, last;

    first = c_vector_begin(p);
    last = c_vector_end(p);
    //printf("free vector is :\n");
    for(iter = first;
          !ITER_EQUAL(iter, last); ITER_INC(iter))
    {
        if(ITER_REF(iter)) {
            free(ITER_REF(iter));
			//c_vector_erase cannot be used here
        }
    }

	//c_vector_erase2(p, c_vector_begin(p), c_vector_end(p));
	c_vector_clear(p);
}

void vector_init(c_pvector *vec, int (*comparer_function)(void *, void *))
{
    *vec = (c_pvector)malloc(sizeof(c_vector));
    if(*vec == NULL) {
    	wpa_printf(MSG_INFO, "malloc vector error......");
    }
    __c_vector(*vec, comparer_function);
}

void vector_deinit(c_pvector *vec)
{
	free_vector(*vec);
	free(*vec);//和c_map不同，此处可以使用free
    __c_rotcev(*vec);
}

void udp_sockfd_init()
{
	if ((odin_udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		wpa_printf(MSG_ERROR, "Create socket error.");
		return;
	}
}

void udp_sockfd_deinit()
{
	close(odin_udp_sockfd);
	odin_udp_sockfd = -1;
}

void udp_send_msg(const u8 *dest, int dest_port, const char *msg) {
	struct sockaddr_in dest_addr;
	char dest_host[30];

	sprintf(dest_host, IPSTR, IP2STR(dest));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(dest_port);
	dest_addr.sin_addr.s_addr = inet_addr(dest_host);

	//udp_sockfd_init();
	if (odin_udp_sockfd == -1) {
		udp_sockfd_init();
	}
	if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
		wpa_printf(MSG_ERROR, "Incorrect ip address!");
		udp_sockfd_deinit();
		return;
	}
	if(sendto(odin_udp_sockfd, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr,
						sizeof(struct sockaddr)) < 0) {
		wpa_printf(MSG_ERROR, "Send message error.");
		udp_sockfd_deinit();
	    return;
	}

//	wpa_printf(MSG_INFO, "Send message:%s", msg);
	//udp_sockfd_deinit();
}

void* ping_thread(void *arg)
{
	while (1) {
		udp_send_msg(swan_conf->controller_ip, swan_conf->udp_dest_port, "ping");
		sleep(2);
	}
}

int ping_thread_init()
{
//  sleep(5);
	if((pthread_create(&odin_thread_id, NULL, (void *) ping_thread, NULL)) != 0) {
		wpa_printf(MSG_ERROR, "Create ping pthread error!");
		return 0;
	}
	return 1;
}

void finish_thread()
{
  	pthread_cancel(odin_thread_id);
 	pthread_join(odin_thread_id, NULL);
}

void* beacon_thread(void *arg)
{
    c_iterator iter, end;
    EtherAddress *dst;
    OdinStationState *state;
    while (1) {
        iter = c_map_begin(_sta_mapping_table);
        end = c_map_end(_sta_mapping_table);

        for(; !ITER_EQUAL(iter, end); ITER_INC(iter))
        {
            dst = (EtherAddress *)(((c_ppair)ITER_REF(iter))->first);
            state = (OdinStationState *)(((c_ppair)ITER_REF(iter))->second);
            send_beacon(*dst, state->_vap_bssid, &(state->_vap_ssids));
//            wpa_printf(MSG_INFO, "send beacon success!");
        }

        usleep(interfaces->iface[0]->bss[0]->iconf->beacon_int*1000);
    }
}

int beacon_thread_init()
{
    if((pthread_create(&beacon_thread_id, NULL, (void *) beacon_thread, NULL)) != 0) {
        wpa_printf(MSG_ERROR, "Create beacon pthread error!");
        return 0;
    }
    return 1;
}

void finish_beacon_thread()
{
    pthread_cancel(beacon_thread_id);
    pthread_join(beacon_thread_id, NULL);
}

/*
void cleanup_lvap(c_pmap rx_stats, int timeout)
{
    c_iterator end, iter;
    StationStats *stat;
    int age;

    end = c_map_end(_rx_stats);
    iter = c_map_begin(_rx_stats);

    for(; !ITER_EQUAL(iter, end); ITER_INC(iter))
    {
        stat = (StationStats *)( ((c_ppair)ITER_REF(iter))->second );
        age = time(NULL) - stat->_last_received;
        if (age > timeout) {
            free(((c_ppair)ITER_REF(iter))->first);
            free(((c_ppair)ITER_REF(iter))->second);
            ((c_ppair)ITER_REF(iter))->first = NULL;
            ((c_ppair)ITER_REF(iter))->second = NULL;
            free(ITER_REF(iter));
            c_map_erase(rx_stats, iter);
        }
    }
}


void* cleanup_thread(void *arg)
{
    while (1) {
        cleanup_lvap(_rx_stats, 30);
        sleep(50);
    }
}

int cleanup_thread_init()
{
    if((pthread_create(&cleanup_thread_id, NULL, (void *) cleanup_thread, NULL)) != 0) {
        wpa_printf(MSG_ERROR, "Create cleanup pthread error!");
        return 0;
    }
    return 1;
}

void finish_cleanup_thread()
{
    pthread_cancel(cleanup_thread_id);
    pthread_join(cleanup_thread_id, NULL);
}
*/

protocol_type protocol_string_to_enum(const char *protocol_str)
{
	int i;

	for(i = 0; i < PROTOCOL_TYPE_NUM; i++) {
		if(strcasecmp(protocol_str, protocol_string[i]) == 0) {
			return (protocol_type)i;
		}
	}
	return (protocol_type)0;
}

char *add_bss_config_file(const char *ctrl_config_path, OdinStationState *state, EtherAddress *sta)
{
    FILE *fp_read, *fp_write, *fp_write_acl;
    char buf_read[1024], buf_write[1024], *buf_read_pos, *bss_config;
    //c_iterator iter, first, last;
    String *ssid;
    char tmp_bss_config[] = "/tmp/run/hostapd-swan.conf";
    char tmp_accept_maclist[] = "/tmp/run/hostapd.acceptmaclist";

    fp_read = fopen(ctrl_config_path, "r");
    fp_write = fopen(tmp_bss_config, "w");
    fp_write_acl = fopen(tmp_accept_maclist, "w");
    bss_config = malloc(sizeof(tmp_bss_config)+16*sizeof(unsigned char));//bss_config=phy0:

    sprintf(bss_config, "bss_config=phy0:%s", tmp_bss_config);

    ssid = &(state->_vap_ssids);
    /*first = c_vector_begin(state->_vap_ssids);
    last = c_vector_end(state->_vap_ssids);
    for(iter = first; !ITER_EQUAL(iter, last); ITER_INC(iter)){
    	if(ITER_REF(iter))
    		ssid = (String *)(ITER_REF(iter));
    }*/

    while (fgets(buf_read, 1024, fp_read) != NULL) {
        buf_read_pos = buf_read;

        if (strstr(buf_read_pos, "interface=wlan0") != NULL) {
            strsep(&buf_read_pos, "=");

            sprintf(buf_write, "%s=%s\n", buf_read, ssid->str);

            wpa_printf(MSG_INFO, "add_bss_config_file : %s", buf_write);
            fputs(buf_write, fp_write);
            continue;
        }
        if (strstr(buf_read_pos, "bssid=") != NULL) {
        	strsep(&buf_read_pos, "=");

            sprintf(buf_write, "%s=%02x:%02x:%02x:%02x:%02x:%02x\n", buf_read, MAC2STR(state->_vap_bssid.mac_addr));

            wpa_printf(MSG_INFO, "add_bss_config_file : %s", buf_write);
            fputs(buf_write, fp_write);
           	continue;
        }
        else if (strstr(buf_read_pos, "ignore_broadcast_ssid=") != NULL) {
        	sprintf(buf_write, "%s", buf_read);
        	//printf("%s", buf_read);
        	fputs(buf_write, fp_write);
        	continue;
        }
        else if (strstr(buf_read_pos, "ssid=") != NULL) {
            strsep(&buf_read_pos, "=");

            sprintf(buf_write, "%s=%s\n", buf_read, ssid->str);

            wpa_printf(MSG_INFO, "add_bss_config_file : %s", buf_write);
            fputs(buf_write, fp_write);
            continue;
        }
        else if (strstr(buf_read_pos, "disassoc_low_ack=") != NULL) {
            strsep(&buf_read_pos, "=");

            sprintf(buf_write, "%s=%d\n", buf_read, 0);

            wpa_printf(MSG_INFO, "add_bss_config_file : %s", buf_write);
            fputs(buf_write, fp_write);
            continue;
        }
        else if (strstr(buf_read_pos, "bridge=") != NULL) {
            continue;
        }


        sprintf(buf_write, "%s", buf_read);
        //printf("%s", buf_read);
        fputs(buf_write, fp_write);
    }

    fputs("macaddr_acl=1\n", fp_write);
    sprintf(buf_write, "accept_mac_file=%s\n", tmp_accept_maclist);
    fputs(buf_write, fp_write);

    sprintf(buf_write, MACSTR, MAC2STR(sta->mac_addr));
    fputs(buf_write, fp_write_acl);

    fclose(fp_read);
    fclose(fp_write);
    fclose(fp_write_acl);

    return bss_config;
//    remove("/tmp/hostapd-swan.conf");

}

int remove_vap (EtherAddress *sta_mac)
{
	c_iterator target, map_end, vector_iter, vector_last;
	String *sta_ssid;
	OdinStationState *state;
	char ovs_del_port_command[50];

	target = c_map_find(_sta_mapping_table, sta_mac);
	map_end = c_map_end(_sta_mapping_table);
	if (ITER_EQUAL(map_end, target)) {
		wpa_printf(MSG_INFO, "The removing VAP is not exist");
		return -1;
	}

	state = (OdinStationState *)(((c_ppair)ITER_REF(target))->second);
	sta_ssid = &(state->_vap_ssids);

	//for remove the bss
	sprintf(ovs_del_port_command, "ovs-vsctl del-port %s %s", OVS_BRIDGE_NAME, sta_ssid->str);
	system(ovs_del_port_command);
	hostapd_remove_iface_odin(interfaces, sta_ssid->str);
	//vector_deinit(&(state->_vap_ssids));

	free(((c_ppair)ITER_REF(target))->first);
	free(((c_ppair)ITER_REF(target))->second);
	((c_ppair)ITER_REF(target))->first = NULL;
	((c_ppair)ITER_REF(target))->second = NULL;
	free(ITER_REF(target));
	c_map_erase(_sta_mapping_table, target);

	return 0;
}

int add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress vap_bssid, String *ssid)
{
	c_iterator target, map_end;
	c_pair *p;
	OdinStationState *state;
	EtherAddress *sta_mac_p;
	char *bss_config;
	char *ctrl_config_path = "/var/run/hostapd-phy0.conf";
	struct sta_info *sta;
	struct hostapd_data *hapd;
	int i;
	char ovs_add_port_command[50];

	u8 supp_rates[4] = {2, 4, 11, 22};
	struct ieee80211_ht_capabilities cap;
//	struct hostapd_hw_modes *current_mode;
//	u16 num_modes;
//	u16 flags;
	//char bss_config[] = "bss_config=phy0:/root/hostapd-swan.conf";

	target = c_map_find(_sta_mapping_table, &sta_mac);
	map_end = c_map_end(_sta_mapping_table);
	if (!ITER_EQUAL(map_end, target))
	{
		wpa_printf(MSG_INFO, "Ignoring VAP add request because it has already been assigned a slot");
		return -1;
	}

	state = (OdinStationState *)malloc(sizeof(OdinStationState) + (ssid->length)*sizeof(unsigned char));
	//state->_vap_bssid = vap_bssid;
	//state->_sta_ip_addr_v4 = sta_ip;
	wpa_printf(MSG_INFO, "vap bssid into add_vap");
	wpa_printf(MSG_INFO, MACSTR, MAC2STR(vap_bssid.mac_addr));
	memcpy(state->_vap_bssid.mac_addr, vap_bssid.mac_addr, ETH_ALEN);
	memcpy(state->_sta_ip_addr_v4.ip, sta_ip.ip, IP_ALEN);
	//state->_vap_ssids = ssid; // _vap_ssids needed to be freed when the lvap is removed
	state->_vap_ssids.length = ssid->length;
	memcpy(state->_vap_ssids.str, ssid->str, (ssid->length)*sizeof(unsigned char));
	sta_mac_p = (EtherAddress *)malloc(sizeof(EtherAddress));
	//*sta_mac_p = sta_mac;
	memcpy(sta_mac_p->mac_addr, sta_mac.mac_addr, ETH_ALEN);

	p = (c_pair *)malloc(sizeof(c_pair));
	*p = c_make_pair(sta_mac_p, state);

	//_sta_mapping_table.set(sta_mac, state);
	wpa_printf(MSG_INFO, "ssid address %x", ssid);
	wpa_printf(MSG_INFO, "state's _vap_ssids address %x", &(state->_vap_ssids));
	//now registing the hostapd beacon frame
    wpa_printf(MSG_INFO, "state's bssid after memcpy");
    wpa_printf(MSG_INFO, MACSTR, MAC2STR(state->_vap_bssid.mac_addr));
	bss_config = add_bss_config_file(ctrl_config_path, state, sta_mac_p);
	wpa_printf(MSG_INFO, "add_vap : %s", bss_config);
	hostapd_add_iface_odin(interfaces, bss_config);

	for (i = 0; i < interfaces->count; i++) {
		if (strcmp(interfaces->iface[i]->conf->bss[0]->iface, "wlan0") == 0)
			hapd = interfaces->iface[i]->bss[interfaces->iface[i]->num_bss - 1];
	}
	sta = ap_sta_add(hapd, sta_mac_p->mac_addr);
	memset(&cap, 0, sizeof(cap));
//	current_mode = hapd->driver->get_hw_feature_data(hapd->drv_priv, &num_modes, &flags);
	//memcpy(cap.supported_mcs_set, current_mode->mcs_set, 16);
	cap.supported_mcs_set[0] = 0xff;
	cap.a_mpdu_params = hapd->iface->current_mode->a_mpdu_params;
	cap.ht_capabilities_info = host_to_le16(HT_CAP_INFO_SHORT_GI20MHZ);
	sta->aid = 0;
	sta->capability = 0x01;
	sta->supported_rates_len = 4;
	memcpy(&(sta->supported_rates), supp_rates, sta->supported_rates_len);
	sta->listen_interval = hapd->iface->conf->beacon_int;
	sta->flags |= WLAN_STA_HT | WLAN_STA_AUTH | WLAN_STA_ASSOC | WLAN_STA_WMM | WLAN_STA_SHORT_PREAMBLE | WLAN_STA_AUTHORIZED;//WPA_STA_AUTHORIZED | WPA_STA_WMM | WPA_STA_SHORT_PREAMBLE;
	sta->qosinfo = 0;
	if (hostapd_sta_add(hapd, sta->addr, sta->aid, sta->capability,
			    sta->supported_rates, sta->supported_rates_len,
			    sta->listen_interval,
			    sta->flags & WLAN_STA_HT ? &cap : NULL,
			    NULL,
			    sta->flags, sta->qosinfo)) {
		wpa_printf(MSG_INFO, "添加不成功");
		free(bss_config);
		free(state);
		free(sta_mac_p);
		free(p);
		return -1;
	}
    c_map_insert(_sta_mapping_table, p);
	free(bss_config);
	sprintf(ovs_add_port_command, "ovs-vsctl add-port %s %s", OVS_BRIDGE_NAME, state->_vap_ssids.str);
	system(ovs_add_port_command);
	return 0;
}

void clear_subscriptions ()
{
	free_vector(_subscription_list);
}

void add_subscription(long subscription_id, EtherAddress sta_addr, String *statistic, relation_t rel, double val)
{
	Subscription *sub = (Subscription *)malloc(sizeof(Subscription) + statistic->length*sizeof(unsigned char));
	sub->subscription_id = subscription_id;
	//sub->sta_addr = sta_addr;
	memcpy(sub->sta_addr.mac_addr, sta_addr.mac_addr, ETH_ALEN);
	memcpy(&(sub->statistic), statistic, sizeof(String) + statistic->length * sizeof(unsigned char));
	sub->rel = rel;
	sub->val = val;
	c_vector_push_back(_subscription_list, sub);
}

static void send_probe_resp(EtherAddress dst, EtherAddress bssid, String *my_ssid)
{
//	u8 *resp;
//	size_t resp_len;
	struct hostapd_data *hapd = interfaces->iface[0]->bss[0];

//	resp = hostapd_gen_probe_resp_odin(hapd, NULL,
//									dst, bssid, my_ssid, 0, &resp_len, 0);
//	if (resp == NULL)
//			return;
	hapd->conf->ssid.ssid_len = my_ssid->length;
	if (os_memcmp(hapd->conf->ssid.ssid, my_ssid->str, my_ssid->length) == 0) {
//	    wpa_printf(MSG_INFO, "handle_probe_resp: have already set network beacon");
	    return;
	}
	wpa_printf(MSG_INFO, "handle_probe_resp: first set network beacon");
	if (hapd->conf->ssid.ssid_len > HOSTAPD_MAX_SSID_LEN ||
			hapd->conf->ssid.ssid_len < 1) {

	}
	else {
		os_memcpy(hapd->conf->ssid.ssid, my_ssid->str, hapd->conf->ssid.ssid_len);
		hapd->conf->ssid.ssid_set = 1;
		hapd->conf->num_accept_mac = 0;
		hapd->conf->macaddr_acl = DENY_UNLESS_ACCEPTED;
		hapd->conf->accept_mac = NULL;
		ieee802_11_set_beacon(hapd);
	}
//	if ((hapd->driver->send_mntr(hapd->drv_priv, resp, resp_len)) < 0)
//		wpa_printf(MSG_INFO, "handle_probe_resp: send failed");
//	if (hostapd_drv_send_mlme(hapd, resp, resp_len, 0) < 0)
//		wpa_printf(MSG_INFO, "handle_probe_resp: send failed");
//	os_free(resp);
}

void send_beacon(EtherAddress dst, EtherAddress bssid, String *my_ssid)
{
    u8 *beacon;
    size_t beacon_len;

    struct hostapd_data *hapd = interfaces->iface[0]->bss[0];
    int i;

    beacon = get_beacon(hapd, dst.mac_addr, bssid.mac_addr, my_ssid->str, my_ssid->length-1, &beacon_len);
    if (beacon == NULL)
            return;

//  wpa_printf(MSG_INFO, "handle_send_beacon: send start");
    if ((hapd->driver->send_mntr(hapd->drv_priv, beacon, beacon_len)) < 0)
        wpa_printf(MSG_INFO, "handle_send_beacon: send failed");
//  if (hostapd_drv_send_mlme(hapd, resp, resp_len, 0) < 0)
//      wpa_printf(MSG_INFO, "handle_probe_resp: send failed");
//  wpa_printf(MSG_INFO, "handle_send_beacon: send success");
    os_free(beacon);
}

void parse_odin_protocol(char *buf, int reply_sock)
{
	char msg[1024] = "";
	char send_msg[1024] = "DATA ";
	char tmp[20];
	char *value, *tp;
	char **recv_msg;
	EtherAddress *iter_key;
	OdinStationState *iter_value;
	protocol_type type;
	c_iterator iter_sta = c_map_begin(_sta_mapping_table);
	c_iterator end_sta = c_map_end(_sta_mapping_table);

	//for the handler_subscriptions write handler
	int num_rows, i;
	long sub_id;
	EtherAddress sta_addr;
	String *statistic;
	relation_t relation;
	double sub_value;

	//for the handler_add_vap write handler
	IPAddress sta_ip;
	EtherAddress sta_mac;
	EtherAddress vap_bssid;
	String *vap_ssid = NULL;
	int num_ssid = 1;
//	int fail = 0;
//	char ack_msg[128] = "";

	// for the handler_probe_response write handler:
	EtherAddress dst_mac;
	EtherAddress dst_bssid;
	String *ssid_no_endchar;

	value = buf;
	tp = strsep(&value, " ");
	//wpa_printf(MSG_INFO, "Incoming......");
	if (strcasecmp(tp, "READ") == 0) {
		tp = strsep(&value, "\n");
		value = tp;
		strsep(&value, ".");
		//wpa_printf(MSG_INFO, "Incoming......");
		type = protocol_string_to_enum(value);
		//wpa_printf(MSG_INFO, "Incoming......");
		switch (type) {
		case handler_view_mapping_table:

			for (; !ITER_EQUAL(iter_sta, end_sta); ITER_INC(iter_sta))
			{
				iter_key = (EtherAddress *)(((c_ppair)ITER_REF(iter_sta))->first);
				iter_value = (OdinStationState *)(((c_ppair)ITER_REF(iter_sta))->second);

				sprintf(tmp, MACSTR, MAC2STR(iter_key->mac_addr));
				strcat(msg, tmp);

				strcat(msg, " ");

				sprintf(tmp, IPSTR,
						IP2STR(iter_value->_sta_ip_addr_v4.ip));
				strcat(msg, tmp);

				strcat(msg, " ");

				sprintf(tmp, MACSTR, MAC2STR(iter_value->_vap_bssid.mac_addr));
				strcat(msg, tmp);

				strcat(msg, " ");
				sprintf(tmp, "%s", iter_value->_vap_ssids.str);
				strcat(msg, tmp);


				strcat(msg, "\n");
		    }
		    break;
		case handler_channel:
		case handler_interval:
		case handler_rxstat:
		case handler_subscriptions:
		case handler_debug:
		case handler_report_mean:
		case handler_spectral_scan:
			break;
		}

		sprintf(tmp, "%d\n", strlen(msg));
		strcat(send_msg, tmp);
		strcat(send_msg, msg);

		if (send(reply_sock, send_msg, strlen(send_msg), 0) == -1) {
			wpa_printf(MSG_INFO, "Send the message error");
		}
		else {
			wpa_printf(MSG_INFO, "Send the message:%s", msg);
		}
	} else if (strcasecmp(tp, "WRITE") == 0){
		tp = strsep(&value, "\n");
		value = tp;
		tp = strsep(&value, " ");
		strsep(&tp, ".");
		type = protocol_string_to_enum(tp);

		switch (type) {
	    case handler_add_vap:
    		tp = strsep(&value, " ");
    		COPY_STR2MAC(tp, sta_mac.mac_addr);
    		//sscanf(tp, MACSTR, sta_mac.mac_addr, sta_mac.mac_addr+1, sta_mac.mac_addr+2,
    		//		sta_mac.mac_addr+3, sta_mac.mac_addr+4, sta_mac.mac_addr+5);
    		tp = strsep(&value, " ");
    		COPY_STR2IP(tp, sta_ip.ip);
    		//sscanf(tp, IPSTR, sta_ip.ip, sta_ip.ip+1, sta_ip.ip+2, sta_ip.ip+3);
    		tp = strsep(&value, " ");
    		COPY_STR2MAC(tp, vap_bssid.mac_addr);
    		//sscanf(tp, MACSTR, vap_bssid.mac_addr, vap_bssid.mac_addr+1, vap_bssid.mac_addr+2,
    		//		vap_bssid.mac_addr+3, vap_bssid.mac_addr+4, vap_bssid.mac_addr+5);
    		wpa_printf(MSG_INFO, "copy src: %s", tp);
            wpa_printf(MSG_INFO, "vap bssid after copy");
            wpa_printf(MSG_INFO, MACSTR, MAC2STR(vap_bssid.mac_addr));
    		tp = value;
    		while (strsep(&value, " "))
    		        num_ssid++;
    		for (; num_ssid > 1; num_ssid--) {
    			if (vap_ssid != NULL) {
    				free(vap_ssid);
    				vap_ssid = NULL;
    			}
    			vap_ssid = (String *)malloc(sizeof(String) + (strlen(tp) + 1)*sizeof(unsigned char) );
    			vap_ssid->length = (strlen(tp) + 1);
    			memcpy(vap_ssid->str, tp, vap_ssid->length);
    			tp += (strlen(tp) + 1);
    		}
    		wpa_printf(MSG_INFO, "vap bssid before add_vap");
    		wpa_printf(MSG_INFO, MACSTR, MAC2STR(vap_bssid.mac_addr));
    		add_vap (sta_mac, sta_ip, vap_bssid, vap_ssid);
    		if (vap_ssid != NULL) {
    			free(vap_ssid);
    		}
/*    		if (fail == 0) {
                strcat(ack_msg, "ack success\n");
    		}
    		else {
    		    strcat(ack_msg, "ack failed\n");
    		}
    		if (send(reply_sock, ack_msg, strlen(ack_msg), 0) == -1) {
    		    wpa_printf(MSG_INFO, "Send the ack error");
    		}*/
	        break;
	    case handler_set_vap:
	    	break;
	    case handler_remove_vap:
	    	tp = strsep(&value, " ");
	    	COPY_STR2MAC(tp, sta_mac.mac_addr);
	    	remove_vap(&sta_mac);
/*            if (fail == 0) {
                strcat(ack_msg, "ack success\n");
            }
            else {
                strcat(ack_msg, "ack failed\n");
            }
            if (send(reply_sock, ack_msg, strlen(ack_msg), 0) == -1) {
                wpa_printf(MSG_INFO, "Send the ack error");
            }*/
	    	break;
	    case handler_channel:
	    case handler_interval:
	    	break;
	    case handler_subscriptions:

	    	clear_subscriptions();

	    	tp = strsep(&value, " ");
	    	num_rows = atoi(tp);
	    	for (i = 0; i < num_rows; i++) {
	    		tp = strsep(&value, " ");
	    		sub_id = atol(tp);
	    		tp = strsep(&value, " ");
	    		COPY_STR2MAC(tp, sta_addr.mac_addr);
	    		//sscanf(tp, MACSTR, sta_addr.mac_addr, sta_addr.mac_addr+1, sta_addr.mac_addr+2,
	    		//		sta_addr.mac_addr+3, sta_addr.mac_addr+4, sta_addr.mac_addr+5);
	    		tp = strsep(&value, " ");
	    		statistic = malloc(sizeof(String) + (strlen(tp) + 1)*sizeof(unsigned char) );
	    		statistic->length = (strlen(tp) + 1);
	    		memcpy(statistic->str, tp, statistic->length);
	    		tp = strsep(&value, " ");
	    		relation = (protocol_type)atoi(tp);
	    		tp = strsep(&value, " ");
	    		sub_value = atof(tp);

	    		add_subscription (sub_id, sta_addr, statistic, relation, sub_value);
	    		free(statistic);
	    		statistic = NULL;
	    	}
	    	break;
	    case handler_debug:
	    case handler_probe_response:

    		tp = strsep(&value, " ");
    		COPY_STR2MAC(tp, dst_mac.mac_addr);
    		//sscanf(tp, MACSTR, &(dst_mac.mac_addr[0]), &(dst_mac.mac_addr[1]), &(dst_mac.mac_addr[2]),
    		//		&(dst_mac.mac_addr[3]), &(dst_mac.mac_addr[4]), &(dst_mac.mac_addr[5]));
    		//wpa_printf(MSG_INFO, "%s", tp);
    		//wpa_printf(MSG_INFO, MACSTR, MAC2STR(dst_mac.mac_addr));
    		//printf("%02x:%02x:%02x:%02x:%02x:%02x", dst_mac.mac_addr[0], dst_mac.mac_addr[1], dst_mac.mac_addr[2],
			//		dst_mac.mac_addr[3], dst_mac.mac_addr[4], dst_mac.mac_addr[5]);

    		tp = strsep(&value, " ");
    		//wpa_printf(MSG_INFO, "%s", tp);
    		COPY_STR2MAC(tp, dst_bssid.mac_addr);
			//sscanf(tp, MACSTR, dst_bssid.mac_addr, dst_bssid.mac_addr+1, dst_bssid.mac_addr+2,
    		//		dst_bssid.mac_addr+3, dst_bssid.mac_addr+4, dst_bssid.mac_addr+5);
    		//wpa_printf(MSG_INFO, MACSTR, MAC2STR(dst_bssid.mac_addr));
    		// FIXME:此处需要添加对多ssid的支持
    		tp = value;
    		while (strsep(&value, " "))
    			num_ssid++;
    		for (; num_ssid > 1; num_ssid--) {
    			ssid_no_endchar = (String *)malloc(sizeof(String) + strlen(tp)*sizeof(unsigned char) );
    			ssid_no_endchar->length = strlen(tp);
    		    memcpy(ssid_no_endchar->str, tp, ssid_no_endchar->length);
    		    send_probe_resp(dst_mac, dst_bssid, ssid_no_endchar);
    		    free(ssid_no_endchar);
    		    tp += (strlen(tp) + 1);
    		}
	    	break;
	    case handler_probe_request:
	    case handler_update_signal_strength:
	    case handler_signal_strength_offset:
	    case handler_spectral_scan:
	    	break;
		}
	}
}

void odin_protocol_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
	int count;
	char buf[BUFFER_SIZE];
	c_iterator iter;
	c_iterator first, last;

	if ((count = recv(sock, buf, BUFFER_SIZE, 0)) > 0) {
		wpa_printf(MSG_INFO, "Receive the message from client:%s", buf);
		//printf("Received a message from %d: %s\n", fd, buf);
		parse_odin_protocol(buf, sock);
	}
	else
	{
		close(sock);
		eloop_unregister_read_sock(sock);

		first = c_vector_begin(client_sock_vector);
		last = c_vector_end(client_sock_vector);

		for(iter = first;
			 !ITER_EQUAL(iter, last); ITER_INC(iter))
		{
			if((*((int *)(ITER_REF(iter)))) == sock) {
				c_vector_erase(client_sock_vector, iter);
			}
		}
		wpa_printf(MSG_INFO, "Client has left");
//		remove_odin_lvaps_all();
	    //printf("Client %d(socket) has left\n", fd);
	}
}

void handle_tcp_client_connection(int sock, void *eloop_ctx, void *sock_ctx)
{
	int client_sockfd, *client;
	struct sockaddr_in client_sockaddr;
	int sin_size;

	if ((client_sockfd = accept(sock, (struct sockaddr *)&client_sockaddr,
		 	 	 	 	 	 &sin_size))== -1) {
		wpa_printf(MSG_INFO, "Could not accept the tcp connection from client");
		return;
	}
	if (eloop_register_read_sock(client_sockfd, odin_protocol_handler,
						     NULL, NULL)) {
		wpa_printf(MSG_INFO, "Could not register odin protocol eloop read socket");
		return;
	}

	wpa_printf(MSG_INFO, "New connection from client");
	client = (int *)malloc(sizeof(int));
	*client = client_sockfd;
	c_vector_push_back(client_sock_vector, client);
}

void odin_protocol_eloop_init(int socket_port_recv)
{
	struct sockaddr_in server_sockaddr;
	int i = 1;/* 使得重复使用本地地址与套接字进行绑定 */

	if ((server_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		wpa_printf(MSG_ERROR, "Create odin protocol server socket error!");
	    return;
	}

	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(socket_port_recv);
	server_sockaddr.sin_addr.s_addr = INADDR_ANY;

	setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	if (bind(server_sockfd, (struct sockaddr *)&server_sockaddr,
						sizeof(struct sockaddr)) == -1) {
		wpa_printf(MSG_ERROR, "Bind odin protocol server socket error!");
		close(server_sockfd);
	    return;
	}
	if(listen(server_sockfd, MAX_QUE_CONN_NM) == -1) {
		wpa_printf(MSG_ERROR, "Listen odin protocol server socket error!");
		close(server_sockfd);
	    return;
	}

	wpa_printf(MSG_INFO, "Listening......");

	if (eloop_register_read_sock(server_sockfd, handle_tcp_client_connection,
					     NULL, NULL)) {
		wpa_printf(MSG_INFO, "Could not register odin protocol eloop read socket");
		return;
	}
}

void odin_protocol_eloop_deinit()
{
	close(server_sockfd);
	eloop_unregister_read_sock(server_sockfd);
}

void params_init()
{
	map_init(&_sta_mapping_table, etheraddress_comparer);
//	map_init(&_rx_stats, etheraddress_comparer);
//	map_init(&_mean_table, etheraddress_comparer);
	vector_init(&_subscription_list, subscription_comparer);
}

void params_deinit()
{
	vector_deinit(&_subscription_list);
//	map_deinit(&_mean_table);
//	map_deinit(&_rx_stats);
	map_deinit(&_sta_mapping_table);
}

//merge into the params_init
void client_sock_init()
{
	client_sock_vector = (c_pvector)malloc(sizeof(c_vector));
	if(client_sock_vector == NULL) {
		wpa_printf(MSG_INFO, "malloc vector error......");
	}
	__c_vector(client_sock_vector, int_comparer);
}

void client_sock_deinit()
{
	c_iterator iter;
	c_iterator first, last;

	first = c_vector_begin(client_sock_vector);
	last = c_vector_end(client_sock_vector);

	for(iter = first;
	     !ITER_EQUAL(iter, last); ITER_INC(iter))
	{
	    if(ITER_REF(iter)) {
	    	close(*((int *)(ITER_REF(iter))));
	    	eloop_unregister_read_sock(*((int *)(ITER_REF(iter))));
	    }
	}

	vector_deinit(&client_sock_vector);
}

void odin_protocol_init_monitor_interface()
{
	int i;
	for (i = 0; i < interfaces->count; i++) {
		/* FIXME:从这个接口传下去一个handler的函数指针 */
		interfaces->iface[i]->bss[0]->driver->create_odin_monitor_interface(interfaces->iface[i]->bss[0]->drv_priv);
	}
}

void odin_protocol_deinit_monitor_interface()
{
	int i;
	for (i = 0; i < interfaces->count; i++) {
		interfaces->iface[i]->bss[0]->driver->remove_odin_monitor_interface(interfaces->iface[i]->bss[0]->drv_priv);
	}
}

void remove_odin_lvaps_all()
{
	//hostapd_remove_iface(interfaces, "wlan0");
	/*
	c_iterator vector_iter, vector_last;
	String *sta_ssid, *ssid;
	OdinStationState *state;
	c_pvector ssids;
	c_iterator iter = c_map_begin(_sta_mapping_table);
	c_iterator end = c_map_end(_sta_mapping_table);

	vector_init(&ssids, string_comparer);

	for(; !ITER_EQUAL(iter, end); ITER_INC(iter))
	{
		state = (OdinStationState *)(((c_ppair)ITER_REF(iter))->second);
		sta_ssid = &(state->_vap_ssids);

		ssid = malloc(sizeof(String)+(sta_ssid->length)*sizeof(unsigned char));
		memcpy(ssid, sta_ssid,
				sizeof(String)+(sta_ssid->length)*sizeof(unsigned char));
		c_vector_push_back(ssids, ssid);
		//for remove the bss
		//hostapd_remove_iface(interfaces, sta_ssid->str);
		wpa_printf(MSG_INFO, "delete %s",sta_ssid->str);
		free(((c_ppair)ITER_REF(iter))->first);
		free(((c_ppair)ITER_REF(iter))->second);
		((c_ppair)ITER_REF(iter))->first = NULL;
		((c_ppair)ITER_REF(iter))->second = NULL;
		free(ITER_REF(iter));
		c_map_erase(_sta_mapping_table, iter);
	}

	vector_iter = c_vector_begin(ssids);
	vector_last = c_vector_end(ssids);
	for(; !ITER_EQUAL(vector_iter, vector_last); ITER_INC(vector_iter))
	{
	    if(ITER_REF(vector_iter)) {
	        hostapd_remove_iface(interfaces,
	        		((String *)(ITER_REF(vector_iter)))->str);
	        wpa_printf(MSG_INFO, "delete %s",
	        		((String *)(ITER_REF(vector_iter)))->str);
	    }
	}
	vector_deinit(&ssids);*/

	/*
	int i, j;
	struct hostapd_iface *hapd_iface;
	char ovs_del_port_command[50];

	for (i = 0; i < interfaces->count; i++) {
		hapd_iface = interfaces->iface[i];
		if (hapd_iface == NULL)
			return;

		while ((hapd_iface->conf->num_bss) > 1) {
			wpa_printf(MSG_INFO, "delete %s", hapd_iface->conf->bss[1]->iface);
			sprintf(ovs_del_port_command, "ovs-vsctl del-port %s %s", OVS_BRIDGE_NAME, hapd_iface->conf->bss[1]->iface);
			system(ovs_del_port_command);
			hostapd_remove_iface_odin(interfaces, hapd_iface->conf->bss[1]->iface);
		}
	}*/

	EtherAddress *sta_mac;

	if (c_map_size(_sta_mapping_table) == 0) {
		return;
	}
	c_iterator erase = c_map_begin(_sta_mapping_table);
	while (1) {
		sta_mac = (EtherAddress *)(((c_ppair)ITER_REF(erase))->first);
		remove_vap(sta_mac);
		if (c_map_size(_sta_mapping_table) == 0) {
			break;
		}
		erase = c_map_begin(_sta_mapping_table);
	}
}

void odin_protocol_init(struct hapd_interfaces *ifaces)
{
	//odin_ping protocol
	//start a new thread
	interfaces = ifaces;
	swan_conf = swan_config_read("/etc/config/swan_config");
	if (swan_conf == NULL) {
	    printf("read swan config error");
	    exit(1);
	}
	odin_protocol_eloop_init(swan_conf->tcp_listen_port);
	udp_sockfd_init();
	params_init();
	ping_thread_init();
//	cleanup_thread_init();
    beacon_thread_init();
	client_sock_init();
	odin_protocol_init_monitor_interface();
}

void odin_protocol_deinit()
{
	remove_odin_lvaps_all();
	odin_protocol_deinit_monitor_interface();
	client_sock_deinit();
	finish_beacon_thread();
//	finish_cleanup_thread();
	finish_thread();
	params_deinit();
	udp_sockfd_deinit();
	odin_protocol_eloop_deinit();

	if(swan_conf)
	    os_free(swan_conf);
}

int odin_send_msg(protocol_type type)
{
	return 0;
}

void match_against_subscriptions(StationStats *stats, EtherAddress *src)
{
	int count = 0;
	char publish_msg[1024] = "";
	char subscription_matches[512] = "";
	char tmp_match[100] = "";
	c_iterator iter, last;
	Subscription *sub;
	EtherAddress zero;

	memset(&zero, 0, sizeof(EtherAddress));
	if (c_vector_size(_subscription_list) == 0)
		return;

	iter = c_vector_begin(_subscription_list);
	last = c_vector_end(_subscription_list);
	for (; !ITER_EQUAL(iter, last); ITER_INC(iter)) {

		sub = ITER_REF(iter);

		if (memcmp( &(sub->sta_addr), &zero, sizeof(EtherAddress) ) != 0
			&& memcmp( &(sub->sta_addr), src, sizeof(EtherAddress) ) != 0 )
			continue;

		/* TODO: Refactor to use a series of hash maps instead */
		switch (sub->rel) {
		case EQUALS: {
			if (sub->statistic.length == (strlen("signal") + 1)
				&& strcmp(sub->statistic.str, "signal") == 0
				&& stats->_signal == sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_signal);
				count++;
			} else if (sub->statistic.length == (strlen("rate") + 1)
				&& strcmp(sub->statistic.str, "rate") == 0
				&& stats->_rate == sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_rate);
				count++;
			} else if (sub->statistic.length == (strlen("noise") + 1)
				&& strcmp(sub->statistic.str, "noise") == 0
				&& stats->_noise == sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_noise);
				count++;
			} else if (sub->statistic.length == (strlen("_packets") + 1)
				&& strcmp(sub->statistic.str, "_packets") == 0
				&& stats->_packets == sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_packets);
				count++;
			}
			break;
		}
		case GREATER_THAN: {
			if (sub->statistic.length == (strlen("signal") + 1)
				&& strcmp(sub->statistic.str, "signal") == 0
				&& stats->_signal > sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_signal);
				count++;
			} else if (sub->statistic.length == (strlen("rate") + 1)
				&& strcmp(sub->statistic.str, "rate") == 0
				&& stats->_rate > sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_rate);
				count++;
			} else if (sub->statistic.length == (strlen("noise") + 1)
				&& strcmp(sub->statistic.str, "noise") == 0
				&& stats->_noise > sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_noise);
				count++;
			} else if (sub->statistic.length == (strlen("_packets") + 1)
				&& strcmp(sub->statistic.str, "_packets") == 0
				&& stats->_packets > sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_packets);
				count++;
			}
			break;
		}
		case LESSER_THAN: {
			if (sub->statistic.length == (strlen("signal") + 1)
				&& strcmp(sub->statistic.str, "signal") == 0
				&& stats->_signal < sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_signal);
				count++;
			} else if (sub->statistic.length == (strlen("rate") + 1)
				&& strcmp(sub->statistic.str, "rate") == 0
				&& stats->_rate < sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_rate);
				count++;
			} else if (sub->statistic.length == (strlen("noise") + 1)
				&& strcmp(sub->statistic.str, "noise") == 0
				&& stats->_noise < sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_noise);
				count++;
			} else if (sub->statistic.length == (strlen("_packets") + 1)
				&& strcmp(sub->statistic.str, "_packets") == 0
				&& stats->_packets < sub->val) {
				sprintf(tmp_match, " %d:%d", sub->subscription_id, stats->_packets);
				count++;
			}
			break;
		}
		}
		strcat(subscription_matches, tmp_match);
	}

	sprintf(publish_msg, "publish %02x:%02x:%02x:%02x:%02x:%02x %d%s\n",
			MAC2STR(src->mac_addr), count, subscription_matches);
	udp_send_msg(swan_conf->controller_ip, swan_conf->udp_dest_port, publish_msg);
	//wpa_printf(MSG_INFO, "match sub: 上传订阅: %s", publish_msg);
}

void update_rx_stats(u8 *addr, int datarate,
		int rssi_signal, int noise)
{
	EtherAddress src;
//	EtherAddress *src_p;
	memcpy(&src, addr, ETH_ALEN);
//	c_pair *p;
//	c_iterator end, target;
	StationStats *stat;

//	end = c_map_end(_rx_stats);
//	target = c_map_find(_rx_stats, &src);

//	if (ITER_EQUAL(end, target)) {
//		src_p = malloc(sizeof(EtherAddress));
		stat = malloc(sizeof(StationStats));

		memset(stat, 0, sizeof(*stat));
//		memcpy(src_p, &src, sizeof(EtherAddress));

//		p = (c_pair *)malloc(sizeof(c_pair));
//		*p = c_make_pair(src_p, stat);
//		c_map_insert(_rx_stats, p);
//	}
//	else {
//		stat = (StationStats *)( ((c_ppair)ITER_REF(target))->second );
//	}

	stat->_rate = datarate;
	stat->_noise = noise;
	stat->_signal = rssi_signal + SIGNAL_OFFSET;
//	stat->_packets++;
	stat->_last_received = time(NULL);

	match_against_subscriptions(stat, &src);
	free(stat);

}

const OdinStationState * get_state_by_sta_mac(EtherAddress sta_mac)
{
	OdinStationState *state = NULL;

	state = (OdinStationState *)c_map_at(_sta_mapping_table, &sta_mac);
	return state;
}

int is_sta_allowed(EtherAddress *sta_mac) {
    c_iterator end, target;

    if (sta_mac == NULL) {
        return 0;
    }

    end = c_map_end(_sta_mapping_table);
    target = c_map_find(_sta_mapping_table, sta_mac);

    if (!ITER_EQUAL(end, target)) {
        return 1;
    }

    return 0;
}

void recv_auth(unsigned char *buf, int len)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) buf;
	unsigned char ssid[HOSTAPD_MAX_SSID_LEN + 1];
	char tmp[SSID_MAX_LEN];
	u16 auth_alg, auth_transaction, status_code;

    if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.auth)) {
        wpa_printf(MSG_INFO, "handle_auth - too short payload (len=%lu)",
               (unsigned long) len);
        return;
    }

	auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
	auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	status_code = le_to_host16(mgmt->u.auth.status_code);
//	wpa_printf(MSG_INFO, "recv auth");
	if (auth_transaction == 1) {
//	    wpa_printf(MSG_INFO, "recv auth request");
	    if (os_memcmp(mgmt->bssid, interfaces->iface[0]->bss[0]->own_addr, ETH_ALEN) == 0) {
	        os_memcpy(ssid, interfaces->iface[0]->bss[0]->conf->ssid.ssid, interfaces->iface[0]->bss[0]->conf->ssid.ssid_len);
	        ssid[interfaces->iface[0]->bss[0]->conf->ssid.ssid_len] = '\0';
	        sprintf(tmp, "probe %02x:%02x:%02x:%02x:%02x:%02x %s\n", MAC2STR(mgmt->sa), ssid);
//	        wpa_printf(MSG_INFO, "recv auth request : %s", tmp);
	        udp_send_msg(swan_conf->controller_ip, swan_conf->udp_dest_port, tmp);
	    }
	}
}

void recv_probe_request(unsigned char *buf, int buf_p_len)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) buf;
	u8 *ptr = NULL;
	u8 ssid_empty = 0;
	char tmp[SSID_MAX_LEN];
	EtherAddress src;
	String *ssid = NULL;
	c_iterator map_end, target;

    struct ieee802_11_elems elems;
    const u8 *ie;
    size_t ie_len;

    ie = mgmt->u.probe_req.variable;

    ie_len = buf_p_len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));

    if (ieee802_11_parse_elems(ie, ie_len, &elems, 0) == ParseFailed) {
        wpa_printf(MSG_INFO, "recvprobe: the length of recv_probe_request is too short");
        return;
    }

    if ((!elems.ssid || !elems.supp_rates)) {
        wpa_printf(MSG_INFO, "odinagent : STA " MACSTR " sent probe request "
               "without SSID or supported rates element",
               MAC2STR(mgmt->sa));
        return;
    }

//wpa_printf(MSG_INFO, "recvprobe: come into the recv_probe_request");
	if(elems.ssid_len == 0) {
//wpa_printf(MSG_INFO, "recvprobe: ssid empty");
		ssid_empty = 1;
	}
	else {
		ssid = malloc(sizeof(String) + (elems.ssid_len + 1)*sizeof(unsigned char));
		ssid->length = (elems.ssid_len + 1);
		if (ssid->length > SSID_MAX_LEN) {
			free(ssid);
			return;
		}
		memcpy(ssid->str, elems.ssid, elems.ssid_len);
		ssid->str[elems.ssid_len] = '\0';
	}

	memcpy(&src, mgmt->sa, ETH_ALEN);

	map_end = c_map_end(_sta_mapping_table);
	target = c_map_find(_sta_mapping_table, &src);

	if (!ITER_EQUAL(map_end, target)) {
		return;
	}
	if (ssid_empty) {
		sprintf(tmp, "probe %02x:%02x:%02x:%02x:%02x:%02x \n", MAC2STR(src.mac_addr));
//wpa_printf(MSG_INFO, "recvprobe : 接收到空ssid的%s", tmp);
		udp_send_msg(swan_conf->controller_ip, swan_conf->udp_dest_port, tmp);
		return;
	}

	sprintf(tmp, "probe %02x:%02x:%02x:%02x:%02x:%02x %s\n", MAC2STR(src.mac_addr), ssid->str);
//wpa_printf(MSG_INFO, "recvprobe : 接收到ssid:%s的%s", ssid->str, tmp);
	udp_send_msg(swan_conf->controller_ip, swan_conf->udp_dest_port, tmp);
	if (ssid != NULL)
		free(ssid);
//wpa_printf(MSG_INFO, "recvprobe : free ssid success");
}

void odin_handle_monitor_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];
	struct ieee80211_radiotap_iterator iter;
	int ret;
	int datarate = 0, ssi_signal = 0, noise = 0;
	int injected = 0, failed = 0, rxflags = 0;

	struct ieee80211_hdr *hdr;
	u16 fc, stype;
	unsigned char *buf_p;
	int len_buf_p;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "nl80211: Monitor socket recv failed: %s",
			   strerror(errno));
		return;
	}

	if (ieee80211_radiotap_iterator_init(&iter, (void*)buf, len, NULL)) {
		wpa_printf(MSG_INFO, "nl80211: received invalid radiotap frame");
		return;
	}

	while (1) {
		ret = ieee80211_radiotap_iterator_next(&iter);
		if (ret == -ENOENT)
			break;
		if (ret) {
			wpa_printf(MSG_INFO, "nl80211: received invalid radiotap frame (%d)",
				   ret);
			return;
		}
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				len -= 4;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			rxflags = 1;
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			injected = 1;
			failed = le_to_host16((*(uint16_t *) iter.this_arg)) &
					IEEE80211_RADIOTAP_F_TX_FAIL;
			break;
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			/* TODO: convert from freq/flags to channel number */
			break;
		case IEEE80211_RADIOTAP_RATE:
			datarate = *iter.this_arg * 0.5;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			ssi_signal = (s8) *iter.this_arg;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			noise = (s8) *iter.this_arg;
			break;
		case IEEE80211_RADIOTAP_MCS:
		    datarate = *iter.this_arg + 1; // FIXME:Need to be calculated correctly
		    break;
		}
	}

    if (rxflags && injected)
        return;

	buf_p = buf + iter._max_length;
	len_buf_p = len - iter._max_length;
	hdr = (struct ieee80211_hdr *) buf_p;
	fc = le_to_host16(hdr->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);


	switch (WLAN_FC_GET_TYPE(fc)) {
	case WLAN_FC_TYPE_MGMT:
	    if (!injected) {
            if ((datarate != 0) && (ssi_signal != 0)) {
                update_rx_stats(hdr->addr2, datarate, ssi_signal, noise);
        //      wpa_printf(MSG_INFO, "odin nl80211: rate is %d Mbps, rssi is %d dbm.", datarate, ssi_signal);
            }
            if (len_buf_p < 24)
                return;
            if (stype == WLAN_FC_STYPE_PROBE_REQ) {
                //wpa_printf(MSG_INFO, "recvprobe : recv the mgmt, type : %d, stype : %d", WLAN_FC_GET_TYPE(fc), stype);
                recv_probe_request(buf_p, len_buf_p);
                return;
            }
            if (stype == WLAN_FC_STYPE_AUTH) {
                recv_auth(buf_p, len_buf_p);
                return;
            }
	    }
		break;
	case WLAN_FC_TYPE_CTRL:
		break;
	case WLAN_FC_TYPE_DATA:
	    if (!injected) {
            if ((datarate != 0) && (ssi_signal != 0)) {
                update_rx_stats(hdr->addr2, datarate, ssi_signal, noise);
        //      wpa_printf(MSG_INFO, "odin nl80211: rate is %d Mbps, rssi is %d dbm.", datarate, ssi_signal);
            }
	    }
		break;
	}

}


static void swan_config_default(struct swan_config *conf)
{
    if (conf != NULL) {
        COPY_STR2IP(CONTROLLER, conf->controller_ip);
        conf->tcp_listen_port = TCP_LISTEN_PORT;
        conf->udp_dest_port = UDP_DEST_PORT;
    }
}

static int swan_config_fill(struct swan_config *conf,
                   char *buf, char *pos, int line)
{
    if (os_strcmp(buf, "controller_ip") == 0) {
        COPY_STR2IP(pos, conf->controller_ip);
    } else if (os_strcmp(buf, "tcp_listen_port") == 0) {
        conf->tcp_listen_port = atoi(pos);
    } else if (os_strcmp(buf, "udp_server_port") == 0) {
        conf->udp_dest_port = atoi(pos);
    }
    return 0;
}

/**
 * swan_config_read - Read and parse a configuration file
 * @fname: Configuration file name (including path, if needed)
 * Returns: Allocated configuration data structure
 */
struct swan_config * swan_config_read(const char *fname)
{
    struct swan_config *conf;
    FILE *f;
    char buf[512], *pos;
    int line = 0;
    int errors = 0;
    size_t i;

    conf = os_zalloc(sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    swan_config_default(conf);

    f = fopen(fname, "r");
    if (f == NULL) {
        wpa_printf(MSG_INFO, "swan_config_read : open configuration file '%s' error\nUsing the default setting", fname);
        wpa_printf(MSG_INFO, IPSTR, IP2STR(conf->controller_ip));
        wpa_printf(MSG_INFO, "tcp_listen_port = %d", conf->tcp_listen_port);
        wpa_printf(MSG_INFO, "udp_server_port = %d", conf->udp_dest_port);
        return conf;
    }

    while (fgets(buf, sizeof(buf), f)) {
        line++;

        if (buf[0] == '#')
            continue;
        pos = buf;
        while (*pos != '\0') {
            if (*pos == '\n') {
                *pos = '\0';
                break;
            }
            pos++;
        }
        if (buf[0] == '\0')
            continue;

        pos = os_strchr(buf, '=');
        if (pos == NULL) {
            wpa_printf(MSG_ERROR, "Line %d: invalid line '%s'",
                   line, buf);
            errors++;
            continue;
        }
        *pos = '\0';
        pos++;
        errors += swan_config_fill(conf, buf, pos, line);
    }

    fclose(f);

    wpa_printf(MSG_INFO, "swan_config_read : open configuration file '%s'", fname);
    wpa_printf(MSG_INFO, IPSTR, IP2STR(conf->controller_ip));
    wpa_printf(MSG_INFO, "tcp_listen_port = %d", conf->tcp_listen_port);
    wpa_printf(MSG_INFO, "udp_server_port = %d", conf->udp_dest_port);
    return conf;
}
