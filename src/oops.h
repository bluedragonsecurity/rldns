/*
 * rldns 1.4
 *  (c) Copyright by Indodev All Rights Reserved 
 * indodev.asia
 * Developed by Antonius (w1sd0m) - bluedragonsec.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _oops_h_
#define _oops_h_
 
static inline unsigned int _find_a_name_at_zones_ret_recursive_or_not(char *a_name);
static inline unsigned int _count_octet_length(char *a_name);
static inline char *do_craft_dns_ns_response(char *qid, char *dns_response, int receive, int zone_uid, char *a_name);
static inline char *do_craft_dns_mx_response(char *qid, char *dns_response, int receive, int zone_uid, char *a_name);
static inline boolean validate_ipv4_octet(char *ipaddr);
static inline char *_set_randomize_a_ip(int zone_uid);
static inline char *get_current_dns_qid(char *msg);
static inline char *n_malloc(int size);
static inline char *craft_dns_aname_response(char *qid, char *dns_response, int receive, char *mode, char *ns_ip_or_a_name);
static inline char *craft_dns_mx_response(char *qid, char *dns_response, int receive);
static inline char *craft_dns_ns_response(char *qid, char *dns_response, int receive);
static inline char *determine_dns_request_type(char *request);
static inline char *rtrim(char *str);
static inline char *ltrim(char *str);
static inline char *trim(char *str);
static inline char *do_craft_dns_aname_response(char *total_res_ip, char *qid, char *dns_response, int receive, int zone_uid);
static inline unsigned int _count_answer_length(char *total_res_ip, char *mode);
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) 
    #if !defined(__ARM_ARCH_7__)  &&  !defined(__ARM_ARCH_7A__)  && !defined(__ARM_ARCH_7R__) && !defined(__ARM_ARCH_7S__)  &&  !defined(__ARM_ARCH_7M__)
	static inline void _do_prctl();
    #endif
    /* rdtsc (read date time stamp) routine from http://www.mcs.anl.gov/~kazutomo/rdtsc.html */
    #if defined(__i386__)  || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
	static __inline__ unsigned long long rdtsc(void);
    #elif defined(__x86_64__) || defined(__amd64__)
	static __inline__ unsigned long long rdtsc(void);
    #else
	#if !defined(__ARM_ARCH_7__)  && !defined(__ARM_ARCH_7A__)  && !defined(__ARM_ARCH_7R__)  && !defined(__ARM_ARCH_7S__)  && !defined(__ARM_ARCH_7M__)
	    fprintf(stderr, "\nrdtsc not supported on your platform ! exit !\n");
	    exit(-1);
	#endif
    #endif
#endif
static inline char *_do_fetch_self_ns(char *full_ns);
static inline void _read_zone_file();
static inline unsigned int _enumerate_cname_at_zone(char *_cname, char *_tmp_aname);
static inline unsigned int _enumerate_octet_at_ns_zone(char *_octet_str, char *_tmp_aname, int rldns_response_id);
static inline char *parse_enumerate_and_fetch_each_octet_and_just_return_a_name(char *msg, int receive_len);
static inline char *do_craft_dns_aname_ns_ip_resolve(char *qid, char *dns_response, int receive, char *ns_ip);
static inline void rldns_log(char *log_type, char *msg);
static void _prepare_logs();
static unsigned int _create_udp_sock();
static void _init_set_cred();
static inline void _sig_handler(int sig);
static inline void *__craft_dns_recursive_query(void *arg);
static inline unsigned int _is_this_valid_a_name(char *a_name);
static void __check_machine_support();
static inline void __send_udp_packet_and_get_teh_reply(char *dns_packet);
static inline unsigned int parse_enumerate_each_octet_and_count_length(char *msg, int receive);
static void rldns_main();
static inline unsigned int _check_str_for_invalid_chars_container(char *str_to_check);
static _st_configurations *_init_read_parse_config();
int daemonize();
static inline char *_last_replace(char *original_str, char *str_to_replace, char *replacer_str);
static inline char _get_last_char_of_str(char *checkme);
static inline unsigned int analyze_invalid_dns_request(char *dns_packet, int receive);
static inline char *_switch_rand(int _rand, int zone_uid);
static inline unsigned int find_element(char *seekat, int num);
static void _rldns_check_cred();
static int nb_bind(int rldns_sock);
static inline char *_set_non_randomize_a_ip(int zone_uid);
static inline  void _msg_terminated_err(char *msg);
static inline long get_file_length_or_line_count(char *filename, char *mode);
static inline void _msg_err(char *msg);
static void _check_config();
static int fcntl_nonblock(int sock_fd);
static int _check_self_and_check_proc(char *self);

#endif
