/****************************************************************************
 *  Copyright (c) 2002 Jungo LTD. All Rights Reserved.
 * 
 *  rg/pkg/hostapd/main/hostapd.c
 *
 *  Developed by Jungo LTD.
 *  Residential Gateway Software Division
 *  www.jungo.com
 *  info@jungo.com
 *
 *  This file is part of the OpenRG Software and may not be distributed,
 *  sold, reproduced or copied in any way.
 *
 *  This copyright notice should not be removed
 *
 */

#include <unistd.h>
#include <stdio.h>

#include <process_funcs.h>
#include <rg_set_utils.h>
#include <main/mt_wsec_daemon.h>
#include <mgt/lib/mgt_utils.h>
#include <mgt/lib/mgt_route.h>
#include <mgt/lib/mgt_radius.h>
#include <obscure.h>

#include <main/mt_wpa_common.h>
#include <main/mt_main.h>

#define CONF_PATH "/etc/hostapd/"

#define LEGACY_CONF_FILENAME "hostapd.conf"
#define LEGACY_HOSTAPD "hostapd_048"

#define WPA_CONF_FILENAME "wpa-ap.conf"
#define TOPOLOGY_CONF_FILENAME "topology_ap.conf"
#define HOSTAPD "hostapd"

#define ENT_STATUS ((wpa_stat_t *)e->ent_status)

typedef struct {
    pid_t pid;
    wpa_port_params_t wpa_params;
    int privacy_enabled;
    int cipher;
    struct {
	int enabled;
	struct in_addr ip;
	u16 port;
	u8 secret[RADIUS_SECRET_LEN]; /* RADIUS secret */
	int pre_auth;
    } radius;

    /* 
     * ACTION_TEC - Added this parameter to distinguish between 
     * Rev-E BHR and Rev-F BHR
     */
    int use_new_hostapd;
} hostapd_wpa_stat_t;

static void hostapd_sigchild_handler(pid_t pid, void *data, int status)
{
    rg_error(LERR, "%s: nas killed unexpectedly, status = %d",
	((dev_if_t *)data)->name, WEXITSTATUS(status));
}

static int hostapd_prepare_conf_file(hostapd_wpa_stat_t *stat, dev_if_t *wl_dev,
    dev_if_t *listen_dev, struct in_addr nas_ip)
{
    char *conf_filename = NULL;
    FILE *conf_file;
    code2str_t pairwise_cipher[] = {
	{.code = CFG_WPA_CIPHER_TKIP, .str = "TKIP"},
	{.code = CFG_WPA_CIPHER_AES, .str = "CCMP"},
	{.code = CFG_WPA_CIPHER_TKIP_AES, .str = "TKIP CCMP"},
	{.code = -1}
    };
    wpa_port_params_t *wpa_params = &stat->wpa_params;

    str_printf(&conf_filename, CONF_PATH WPA_CONF_FILENAME);
    conf_file = fopen(conf_filename, "w");
    str_free(&conf_filename);
    if (!conf_file)
    {
	rg_error_f(LERR, "openning conf file:%s failed:%m", WPA_CONF_FILENAME);
	return -1;
    }

    fprintf(conf_file, "ignore_file_errors=1\n");
    fprintf(conf_file, "\n");

    fprintf(conf_file, "logger_syslog=-1\n");
    fprintf(conf_file, "logger_syslog_level=2\n");
    fprintf(conf_file, "logger_stdout=-1\n");
    fprintf(conf_file, "logger_stdout_level=2\n");
    fprintf(conf_file, "\n");

    fprintf(conf_file, "# Debugging: 0 = no, 1 = minimal, 2 = verbose, 3 = msg dumps, 4 = excessive\n");
    fprintf(conf_file, "debug=0\n");
    fprintf(conf_file, "\n");

    fprintf(conf_file, "ctrl_interface=/var/run/hostapd\n");
    fprintf(conf_file, "ctrl_interface_group=0\n");
    fprintf(conf_file, "\n");

    fprintf(conf_file, "##### IEEE 802.11 related configuration #######################################\n\n");

    fprintf(conf_file, "ssid=%s\n", wpa_params->ssid);
    fprintf(conf_file, "dtim_period=%d\n", wpa_params->dtim_period);
    fprintf(conf_file, "max_num_sta=255\n");
    fprintf(conf_file, "macaddr_acl=0\n");
    fprintf(conf_file, "auth_algs=%d\n", wpa_params->auth_alg);
    fprintf(conf_file, "ignore_broadcast_ssid=0\n");
    fprintf(conf_file, "wme_enabled=0\n");
    fprintf(conf_file, "#ap_max_inactivity=300\n");
    fprintf(conf_file, "\n");

#if 0
    fprintf(conf_file, "##### IEEE 802.1X-2004 related configuration ##################################\n\n");
    fprintf(conf_file, "ieee8021x=0\n");
    fprintf(conf_file, "eapol_version=2\n");
    fprintf(conf_file, "#eap_message=hello\0networkid=netw,nasid=foo,portid=0,NAIRealms=example.com\n");
    fprintf(conf_file, "#wep_key_len_broadcast=5\n");
    fprintf(conf_file, "#wep_key_len_unicast=5\n");
    fprintf(conf_file, "#wep_rekey_period=300\n");
    fprintf(conf_file, "eapol_key_index_workaround=0\n");
    fprintf(conf_file, "#eap_reauth_period=3600\n");
    fprintf(conf_file, "#use_pae_group_addr=1\n\n");

    fprintf(conf_file, "##### Integrated EAP server ###################################################\n\n");
    fprintf(conf_file, "eap_server=1\n");
    fprintf(conf_file, "eap_user_file=/etc/wpa2/hostapd.eap_user\n");
    fprintf(conf_file, "#ca_cert=/etc/wpa2/hostapd.ca.pem\n");
    fprintf(conf_file, "#server_cert=/etc/wpa2/hostapd.server.pem\n");
    fprintf(conf_file, "#private_key=/etc/wpa2/hostapd.server.prv\n");
    fprintf(conf_file, "#private_key_passwd=secret passphrase\n");
    fprintf(conf_file, "#check_crl=1\n");
    fprintf(conf_file, "#eap_sim_db=unix:/tmp/hlr_auc_gw.sock\n\n");

    fprintf(conf_file, "##### IEEE 802.11f - Inter-Access Point Protocol (IAPP) #######################\n\n");
    fprintf(conf_file, "#iapp_interface=eth0\n\n");
#endif

    /* RADIUS client configuration for 802.1x */
    if (stat->radius.enabled)
    {
	fprintf(conf_file, "##### RADIUS client configuration #############################################\n\n");

	/* 
	 * If there is no route to radius server, the NAS IP is 0.0.0.0 and
	 * authentication will not succeed. This is better then disabling radius
	 * since then not security is defined 
	 */
	fprintf(conf_file, "nas_identifier=%s\n", inet_ntoa(nas_ip)); 
	
	fprintf(conf_file, "\n# RADIUS authentication server\n\n");
	fprintf(conf_file, "auth_server_addr=%s\n", inet_ntoa(stat->radius.ip));
	fprintf(conf_file, "auth_server_port=%d\n", stat->radius.port);
	fprintf(conf_file, "auth_server_shared_secret=%s\n", stat->radius.secret);
	fprintf(conf_file, "\n");
    }

    if (stat->radius.enabled)
    {
	fprintf(conf_file, "##### IEEE 802.1X-2004 related configuration #################################\n\n");

	fprintf(conf_file, "ieee8021x=1\n");

	/* If 802.1x mode with dynamic WEP keys. */
	if ((wpa_params->allowed_sta_types & WPA_STA_TYPE_WEP_8021X) &&
	    wpa_params->rekeying_wep_cipher)
	{
	    int key_len;
	    key_type_t dummy;

	    cipher_to_key_type(wpa_params->rekeying_wep_cipher, &dummy, &key_len);
	    fprintf(conf_file, "wep_key_len_broadcast=%d\n", key_len);
	    fprintf(conf_file, "wep_key_len_unicast=%d\n", key_len);
	    fprintf(conf_file, "wep_rekey_period=%d\n", wpa_params->gtk_update_interval/1000);
	}
	fprintf(conf_file, "\n");
    }

    if (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA_ANY)
    {
	char *key_mgmt = "WPA-PSK"; 
	
	fprintf(conf_file, "##### WPA/IEEE 802.11i configuration ##########################################\n\n");

	fprintf(conf_file, "wpa=%d\n",
	    (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA1 ? 1 : 0) |
	    (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA2 ? 2 : 0));

	switch (wpa_params->psk_param)
	{
	    case WPA_PSK_PARAM_HEX:
		{
		    char hex_key[2 * WPA_PSK_KEY_LEN + 1];

		    bin_2_hex(hex_key, wpa_params->psk.hex.data, WPA_PSK_KEY_LEN);
		    fprintf(conf_file, "wpa_psk=%s\n", hex_key);
		}
		break;
	    case WPA_PSK_PARAM_ASCII:
		fprintf(conf_file, "wpa_passphrase=%s\n", wpa_params->psk.ascii);
		break;
	    case WPA_PSK_PARAM_NONE:
		key_mgmt = "WPA-EAP";
		break;
	}
	fprintf(conf_file, "wpa_key_mgmt=%s\n", key_mgmt);
	fprintf(conf_file, "wpa_pairwise=%s\n", code2str(pairwise_cipher, stat->cipher));
	fprintf(conf_file, "wpa_group_rekey=%d\n", wpa_params->gtk_update_interval/1000);

	/* WPA2 pre-authentication */
	if ((wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA2) &&
	    stat->radius.enabled && stat->radius.pre_auth)
	{
	    fprintf(conf_file, "rsn_preauth=1\n");
	    fprintf(conf_file, "rsn_preauth_interfaces=%s\n", listen_dev->name);
	}

	//fprintf(conf_file, "#wpa_strict_rekey=1\n");
	//fprintf(conf_file, "#wpa_gmk_rekey=86400\n");
	//fprintf(conf_file, "#peerkey=1\n");
	//fprintf(conf_file, "#ieee80211w=0\n\n");
	fprintf(conf_file, "\n");
    }
    else
	fprintf(conf_file, "wpa=0\n");

    fprintf(conf_file, "##### wps_properties #####################################\n");
    fprintf(conf_file, "wps_disable=1\n");
    fprintf(conf_file, "wps_upnp_disable=1\n");
    fprintf(conf_file, "\n");

    fclose(conf_file);
    return 0;
}

static int hostapd_048_prepare_conf_file(hostapd_wpa_stat_t *stat, dev_if_t *wl_dev,
    dev_if_t *listen_dev, struct in_addr nas_ip)
{
    char *conf_filename = NULL;
    FILE *conf_file;
    code2str_t pairwise_cipher[] = {
	{.code = CFG_WPA_CIPHER_TKIP, .str = "TKIP"},
	{.code = CFG_WPA_CIPHER_AES, .str = "CCMP"},
	{.code = CFG_WPA_CIPHER_TKIP_AES, .str = "TKIP CCMP"},
	{.code = -1}
    };
    dev_if_t *br;
    wpa_port_params_t *wpa_params = &stat->wpa_params;

    str_printf(&conf_filename, CONF_PATH "%s_" LEGACY_CONF_FILENAME,
	wl_dev->name);
    conf_file = fopen(conf_filename, "w");
    str_free(&conf_filename);
    if (!conf_file)
    {
	rg_error_f(LERR, "openning conf file:%s failed:%m", LEGACY_CONF_FILENAME);
	return -1;
    }
    
    /* basic params */
    fprintf(conf_file, "interface=%s\n", wl_dev->name);
   
    /* Add bridge if exist 
     * TODO: Make sure we get notification for bridge change */
    if ((br = enslaving_default_bridge_get(wl_dev)))
	fprintf(conf_file, "bridge=%s\n", br->name);

    /* RADIUS client configuration for 802.1x */
    if (stat->radius.enabled)
    {
	/* If there is no route to radius server, the NAS IP is 0.0.0.0 and
	 * authentication will not succeed. This is better then disabling radius
	 * since then not security is defined */
	fprintf(conf_file, "own_ip_addr=%s\n", inet_ntoa(nas_ip));

	fprintf(conf_file, "auth_server_addr=%s\n", inet_ntoa(stat->radius.ip));
	fprintf(conf_file, "auth_server_port=%d\n", stat->radius.port);
	fprintf(conf_file, "auth_server_shared_secret=%s\n", stat->radius.secret);

	fprintf(conf_file, "ieee8021x=1\n");

	/* If 802.1x mode with dynamic WEP keys. */
	if ((wpa_params->allowed_sta_types & WPA_STA_TYPE_WEP_8021X) &&
	    wpa_params->rekeying_wep_cipher)
	{
	    int key_len;
	    key_type_t dummy;

	    cipher_to_key_type(wpa_params->rekeying_wep_cipher, &dummy,
		&key_len);
	    fprintf(conf_file, "wep_key_len_broadcast=%d\n", key_len);
	    fprintf(conf_file, "wep_key_len_unicast=%d\n", key_len);
	    fprintf(conf_file, "wep_rekey_period=%d\n",
		wpa_params->gtk_update_interval/1000);
	}
    }

    /* WPA/IEEE 802.11i configuration */
    if (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA_ANY)
    {
	char *key_mgmt = "WPA-PSK";

	fprintf(conf_file, "wpa=%d\n",
	    (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA1 ? 1 : 0) |
	    (wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA2 ? 2 : 0));

	/* WPA2 pre-authentication */
	if ((wpa_params->allowed_sta_types & WPA_STA_TYPE_WPA2) &&
	    stat->radius.enabled && stat->radius.pre_auth)
	{
	    fprintf(conf_file, "rsn_preauth=1\n");
	    fprintf(conf_file, "rsn_preauth_interfaces=%s\n", listen_dev->name);
	}

	switch (wpa_params->psk_param)
	{
	case WPA_PSK_PARAM_HEX:
	    {
		char hex_key[2 * WPA_PSK_KEY_LEN + 1];

		bin_2_hex(hex_key, wpa_params->psk.hex.data, WPA_PSK_KEY_LEN);
		fprintf(conf_file, "wpa_psk=%s\n", hex_key);
	    }
	    break;
	case WPA_PSK_PARAM_ASCII:
	    fprintf(conf_file, "wpa_passphrase=%s\n", wpa_params->psk.ascii);
	    break;
	case WPA_PSK_PARAM_NONE:
	    key_mgmt = "WPA-EAP";
	    break;
	}
	fprintf(conf_file, "wpa_key_mgmt=%s\n", key_mgmt);
	fprintf(conf_file, "wpa_pairwise=%s\n", code2str(pairwise_cipher,
	    stat->cipher));
	fprintf(conf_file, "wpa_group_rekey=%d\n",
	    wpa_params->gtk_update_interval/1000);

	/* XXX add the wpa2 preauth stuff */
    }
    else
	fprintf(conf_file, "wpa=0\n");

    fclose(conf_file);
    return 0;
}


static void hostapd_start(void *context, dev_if_t *wl_dev,
    dev_if_t *listen_dev, struct in_addr nas_ip)
{
    if(!strcmp(wl_dev->name,"ath1"))
        return;

    hostapd_wpa_stat_t *stat = context;
    char *cmd = NULL;

    /* Don't activate hostapd for WEP or disabled mode. */
    if ((stat->wpa_params.allowed_sta_types & WPA_STA_TYPE_WEP_LEGACY) ||
	!stat->wpa_params.allowed_sta_types || !stat->privacy_enabled)
    {
	return;
    }

    if (stat->use_new_hostapd)
    {
	hostapd_prepare_conf_file(stat, wl_dev, listen_dev, nas_ip);
	str_printf(&cmd, HOSTAPD " " CONF_PATH TOPOLOGY_CONF_FILENAME);
    }
    else
    {
	hostapd_048_prepare_conf_file(stat, wl_dev, listen_dev, nas_ip);
	str_printf(&cmd, LEGACY_HOSTAPD " " CONF_PATH "%s_" LEGACY_CONF_FILENAME, wl_dev->name);
    }

    console_printf("\n%s: hostapd_cmd=%s\n", __FUNCTION__, cmd);
    stat->pid = start_process(cmd, SYSTEM_DAEMON, hostapd_sigchild_handler, wl_dev);
    rg_error(LINFO, "%s:wl_dev(%s), listen_dev(%s), hostapd(pid = %d) started",
                __FUNCTION__, wl_dev->name, listen_dev->name, stat->pid);
    str_free(&cmd);
}

static void hostapd_stop(void *context)
{
    hostapd_wpa_stat_t *stat = context;

    if (stat->pid == -1)
	return;

    rg_error(LINFO, "%s: hostapd(pid = %d) stop", __FUNCTION__, stat->pid);
    stop_process(stat->pid);
    stat->pid = -1;
}

static void hostapd_wpa_stat_fill(hostapd_wpa_stat_t *stat, dev_if_t *dev)
{
    set_t **wpa_set = set_get(dev_if_set(dev), Swpa);

    wpa_port_params_fill(dev, NULL, &stat->wpa_params);
    
    if (stat->wpa_params.psk_param == WPA_PSK_PARAM_ASCII)
	stat->wpa_params.psk.ascii = strdup(stat->wpa_params.psk.ascii);
    //stat->wpa_params.ssid = NULL; /* not used */
    stat->privacy_enabled = wlan_is_privacy_enabled(dev_if_set(dev));
    stat->cipher = set_get_path_enum(wpa_set, Scipher,
	cfg_wpa_cipher_t_str);
    stat->radius.enabled = (set_get_path_flag(wpa_set, Sprivacy_enabled) &&
        (stat->wpa_params.allowed_sta_types & WPA_STA_TYPE_WEP_8021X ||
	(stat->wpa_params.allowed_sta_types & WPA_STA_TYPE_WPA_ANY &&
	stat->wpa_params.psk_param == WPA_PSK_PARAM_NONE)));

    if (stat->radius.enabled)
    {
	set_t **radius = set_get(wpa_set, Sradius);

	if (radius)
	{
	    stat->radius.ip = set_get_path_ip(radius, Sip);
	    stat->radius.port = set_get_path_int(radius, Sport);
	    strncpy(stat->radius.secret,
		set_get_path_strz(radius, Sshared_secret), RADIUS_SECRET_LEN);
	    unobscure_str(stat->radius.secret);
	    stat->radius.pre_auth = set_get_path_flag(wpa_set,
  	                 S8021x "/" Spre_auth);
	}
    }
}

static void hostapd_wpa_stat_free(hostapd_wpa_stat_t *stat)
{
    if (stat->wpa_params.psk_param == WPA_PSK_PARAM_ASCII)
	free(stat->wpa_params.psk.ascii);
}

static void hostapd_wpa_reconf(void *context, dev_if_t *dev)
{
    if(!strcmp(dev->name,"ath1"))
        return;

    hostapd_wpa_stat_t *stat = context;

    hostapd_stop(stat);
    hostapd_wpa_stat_free(stat);
    hostapd_wpa_stat_fill(stat, dev);
}

static reconf_type_t hostapd_wpa_changed(void *context, dev_if_t *dev)
{
    set_t **old, **new;
    
    old = dev_if_set_get(&saved_rg_conf, dev);
    new = dev_if_set_get(rg_conf, dev);

    if (COMP_SET(old, new, Swpa) || 
	COMP_SET(old, new, S8021x) ||
	COMP_SET(old, new, Swlan))
    {
	return NEED_RECONF;
    }
	
    return NO_RECONF;
}

struct in_addr hostapd_get_radius_ip(void *context)
{
    hostapd_wpa_stat_t *stat = context;
    struct in_addr ip = { 0 };

    if (stat->radius.enabled)
	return stat->radius.ip;

    return ip;
}

static wsec_daemon_cb_t hostapd_wpa_daemon_cb = {
    .start_daemon = hostapd_start,
    .stop_daemon = hostapd_stop,
    .get_radius_ip = hostapd_get_radius_ip,
    .changed = hostapd_wpa_changed,
    .reconf = hostapd_wpa_reconf,
};

void __hostapd_wpa_open(void *ctx)
{
    dev_if_t *dev = ctx;
    hostapd_wpa_stat_t *stat = zalloc_e(sizeof(hostapd_wpa_stat_t));

#ifdef CONFIG_HW_AUTODETECT
    int actiontec_is_new_hostapd(void);
    stat->use_new_hostapd = actiontec_is_new_hostapd();
#endif
    stat->pid = -1;

    console_printf("Starting HOSTAPD on dev '%s'\n", dev->name);
    mt_wsec_daemon_open(dev, &hostapd_wpa_daemon_cb, stat);
}

void hostapd_wpa_close(dev_if_t *dev)
{
    if(!strcmp(dev->name,"ath1"))
        return;

    event_timer_del(__hostapd_wpa_open, dev);

    rg_entity_t *e = dev->context_wsec_daemon;
    hostapd_wpa_stat_t *stat = mt_wsec_daemon_get_context(e);

    mt_wsec_daemon_close(e);
    hostapd_wpa_stat_free(stat);
    free(stat);
}

void hostapd_wpa_open(dev_if_t *dev)
{
    if(!strcmp(dev->name,"ath1"))
        return;

    console_printf("Scheduling HOSTAPD on dev '%s'\n", dev->name);
    event_timer_set(10000, __hostapd_wpa_open, dev);
}
