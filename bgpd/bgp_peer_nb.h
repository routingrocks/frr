#ifndef _FRR_BGP_PEER_NB_H_
#define _FRR_BGP_PEER_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

const void *lib_vrf_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_id_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_vrf_peer_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_peer_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_vrf_peer_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_peer_name_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_vrf_peer_afi_safi_get_next(struct nb_cb_get_next_args *args);
struct yang_data *
lib_vrf_peer_afi_safi_rcvd_pfx_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_status_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_in_queue_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_out_queue_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_tx_updates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_rx_updates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_local_as_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_as_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_last_established_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_description_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_neighbor_address_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_messages_sent_last_notification_error_code_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_messages_received_last_notification_error_code_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_group_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_type_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_gshut_get_elem(struct nb_cb_get_elem_args *args);
int lib_vrf_peer_afi_safi_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_vrf_peer_afi_safi_lookup_entry(struct nb_cb_lookup_entry_args *args);
const void *lib_vrf_peer_afi_safi_get_next(struct nb_cb_get_next_args *args);
struct yang_data *lib_vrf_peer_afi_safi_afi_safi_name_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_installed_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_afi_safi_pfx_sent_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_afi_safi_afi_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_afi_safi_safi_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_total_msgs_sent_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_total_msgs_recvd_get_elem(struct nb_cb_get_elem_args *args);
extern const struct frr_yang_module_info frr_bgp_peer_info;

struct yang_data *lib_peer_status_get_elem(struct nb_cb_get_elem_args *args);
void bgpd_peer_notify_event(struct peer *peer);

#ifdef __cplusplus
}
#endif
#endif
