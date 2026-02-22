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

#include "headers.h"
#include "vars.h"
#include "structs.h"
#include "oops.h"

static inline unsigned int _find_a_name_at_zones_ret_recursive_or_not(char *a_name)
{
	int i, recursive_req = 1;
	
	/* enumerate dns zone at struct to find match */
	for (i = 0; i < zone_count; i++) {
		if ((strcmp((_ret_st_mainstruct_domain_zone + i)->domain_zone, a_name)) == 0) {
			recursive_req = 0;
			break;
		}
	}	
	
	return recursive_req;
}

static inline char *_set_non_randomize_a_ip(int zone_uid)
{
	char *total_ip_sequence, *tmp_ip = NULL;
	int i, how_many = 1;
	boolean valid;
	
	how_many = (_ret_st_mainstruct_domain_zone + zone_uid)->domain_zone_a_ip_count;
	if (how_many == 0)
		how_many = 1;
	total_ip_sequence = n_malloc((16 * how_many) + (how_many - 1));
	for (i = 1; i <= how_many; i++) {
		if ((_ret_struct_a_res + zone_uid)->a_ip[i] != NULL) 
			tmp_ip = (_ret_struct_a_res + zone_uid)->a_ip[i];
		if (tmp_ip != NULL) {
			if ((strstr(tmp_ip, ".") != NULL) && (strlen(tmp_ip) > 2) && (strlen(tmp_ip) <=16) ) {
				valid = validate_ipv4_octet(tmp_ip);
				if (valid == _true) {
					#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
					strlcat(total_ip_sequence, tmp_ip, 16);
					strlcat(total_ip_sequence, "|", 1);
					#else
					strncat(total_ip_sequence, tmp_ip, 16);
					strcat(total_ip_sequence, "|");
					#endif
				}
			}
		}
	}	
	if (total_ip_sequence == NULL)
                return (char *)'\0';
	total_ip_sequence = _last_replace(total_ip_sequence, "|", "");
	
	return total_ip_sequence;
}

static unsigned int _create_udp_sock()
{
	int rldns_sock  = 0;	
	
	if ((rldns_sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) 
		_msg_terminated_err(sock_fail);
	if (setsockopt(rldns_sock, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) == -1) 
		_msg_err(fail_reuseaddr);
	
	return rldns_sock;
}

static unsigned int cont_or_no()
{
	char y_or_n;
	
	fprintf(stdout, "\n Warning ! Failed to set non blocking socket ! No concurreny, server may not handle multiple client ! Do you want to continue running server ? (y/n)");	
	y_or_n = (char)getchar();
	
	return (int)(y_or_n);
}

static int nb_bind(int rldns_sock)
{
	int y_or_n  = 0;	
	
	if ((rldns_sock = fcntl_nonblock(rldns_sock)) < 0) {
		y_or_n = cont_or_no();
		if ((y_or_n == 0x6e) || (y_or_n == 0x4e))
			exit(0);
	}
	server_addr.sin_family = AF_INET;         
        server_addr.sin_port = htons(rldns_port);     
        server_addr.sin_addr.s_addr = INADDR_ANY; 
        bzero(&(server_addr.sin_zero), 8); 
	if (bind(rldns_sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) < 0) 
		_msg_terminated_err(fail_bind);

	return rldns_sock;
}

static void _init_set_cred()
{
	int rldns_uid, rldns_gid, res;
	struct passwd *p;

	if ((p = getpwnam(user)) == NULL) 
		_msg_terminated_err(no_user);		
	rldns_uid = (int) (p->pw_uid);
	rldns_gid =  (int) (p->pw_gid);
	res = setgid(rldns_gid);
	if (res == -1)
		_msg_err(fail_to_setgid);
	res = setegid(rldns_gid);
	if (res == -1)
		_msg_err(fail_to_setegid);
	res = setregid(rldns_gid, rldns_gid);
	if (res == -1)
		_msg_err(fail_to_setregid);
	res = seteuid(rldns_uid);
	if (res == -1)
		_msg_err(fail_to_seteuid);
	#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) 	
	res = setreuid(rldns_uid, rldns_uid);
	if (res == -1)
		_msg_err(fail_to_setreuid);
	#endif
	res = setuid(rldns_uid);
	if (res == -1)
		_msg_err(fail_to_setuid);
}

static inline void *__craft_dns_recursive_query(void *arg)
{
	int valid = 0;
	/* add thread safety from : http://en.wikipedia.org/wiki/Thread_safety */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
 
	(void)arg;
	pthread_mutex_lock(&mutex);
 	if (generic_packet != NULL) {
		if ((recursive_dns1 != NULL) && (recursive_dns2 != NULL)) {
			if (strlen(recursive_dns1) > 0) {
				valid = _is_this_valid_a_name(generic_a_name);
				if (valid == 1) 
					__send_udp_packet_and_get_teh_reply(generic_packet);
			}
		}
	}
	pthread_mutex_unlock(&mutex);
	pthread_detach(pthread_self());
	
	return (void *)(intptr_t)valid;
}

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) 
/**
prctl and rdtsc reference taken from :
http://man7.org/linux/man-pages/man2/prctl.2.html
http://www.mcs.anl.gov/~kazutomo/rdtsc.html
Trying to get timestamp for seeding random() later, cr4 register control must be enabled 
**/
    #if !defined(__ARM_ARCH_7__)  &&  !defined(__ARM_ARCH_7A__)  && !defined(__ARM_ARCH_7R__) && !defined(__ARM_ARCH_7S__)  &&  !defined(__ARM_ARCH_7M__)
	static inline void _do_prctl()
	{
	    if (already_prctl == 0) {
		if ((prctl(PR_SET_TSC, PR_TSC_ENABLE)) == -1) {
			_msg_err(failed_prctl);
		}
		already_prctl = 1;
	    }
	}
    #endif
	/* rdtsc (read date time stamp) routine from http://www.mcs.anl.gov/~kazutomo/rdtsc.html */
	#if defined(__i386__) || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
		static __inline__ unsigned long long rdtsc(void)
		{
			unsigned long long int x;
			__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
	
			return x;
		}
	#elif defined(__x86_64__) || defined(__amd64__)
	static __inline__ unsigned long long rdtsc(void)
	{
		unsigned hi, lo;
	
		__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  
		return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
	}
	#else
		#if !defined(__ARM_ARCH_7__)  &&  !defined(__ARM_ARCH_7A__)  && !defined(__ARM_ARCH_7R__) && !defined(__ARM_ARCH_7S__)  &&  !defined(__ARM_ARCH_7M__)
		fprintf(stderr, "\nrdtsc not supported on your platform ! exit !\n");
		exit(-1);
		#else
		/* modified from http://stackoverflow.com/questions/21594140/c-how-to-ensure-different-random-number-generation-in-c-when-program-is-execut */
		static __inline__ unsigned long long seed_rng(void){
		    unsigned long long retme;
		    int fp;
		    unsigned seed = 0;
		    unsigned pos = 0;
		    
		    fp = open("/dev/urandom", O_RDONLY);
		    while (pos < sizeof(seed)) {
			int amt = read(fp, (char *) &seed + pos, sizeof(seed) - pos);
			if (amt <= 0) abort();
			    pos += amt;
		    }
		    retme = (unsigned long long)seed;
		    
		    return retme;
		}
		#endif
	#endif
#endif

static inline char *_switch_rand(int _rand, int zone_uid)
{
	char *my_tmp_ip = NULL;
	
	if (_rand == 0)
		_rand = 1;
	if ((_rand > -1) && (_rand < 19)) {
		if ((((_ret_struct_a_res) + zone_uid)->a_ip[_rand] != NULL) && (sizeof(((_ret_struct_a_res) + zone_uid)->a_ip[_rand]) >= divide_by)) 		
			my_tmp_ip = ((_ret_struct_a_res) + zone_uid)->a_ip[_rand];	
	}
	if (my_tmp_ip == NULL)
                return (char *)'\0';
	
	return my_tmp_ip;
}

static inline unsigned int _count_answer_length(char *total_res_ip, char *mode)
{
	char *piece;
	int leng_tot_ip = 0, num_of_ans = 0, ret = 0;
	
	if ((total_res_ip != NULL) && sizeof(total_res_ip) > 0) {
		piece = strtok(total_res_ip, "|");
		while (piece != NULL) {
			if (strcmp(mode, "length") == 0) {
				leng_tot_ip += (int)strlen(piece);
				leng_tot_ip += 10;
				ret = leng_tot_ip;
			}
			else if (strcmp(mode, "answer_count") == 0) 
				num_of_ans++;	
			piece = strtok(NULL, "|");
		}
		if (strcmp(mode, "length") == 0) 
			ret = leng_tot_ip;
		else if (strcmp(mode, "answer_count") == 0) 
			ret = num_of_ans;	
	}
	
	return ret;
}

static inline void _sig_handler(int sig)
{
	pid_t pid;
	int status = 0;
	
	(void)sig;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		return;
}

static inline long get_file_length_or_line_count(char *filename, char *mode)
{
	FILE *fd = NULL;
	int retfunc = 0, filename_len = 0, len = 0, retval = 0, tot = 0;
	char str[256] = "\0";
	char *pcs, *fgets_retval_check;  
	
	filename_len = (int) strlen(filename);
	tot = filename_len + 7;
	char cmd[tot];  

	if (filename) {
		if (strlen(filename) > 0) {
			if (strstr(mode, "lengt") != NULL) {
				retfunc = snprintf(cmd, sizeof(cmd), "wc -c %s", filename);
				if (retfunc == 0) {
					retval = 0;
					goto out_get_file_length_or_line_count;
				}
			}
			else {
				retfunc = snprintf(cmd, sizeof(cmd), "wc -l %s", filename);
				if (retfunc == 0) {
					retval = 0;
					goto out_get_file_length_or_line_count;
				}
			}
			fd = popen(cmd,"r");
			if (fd != NULL) {	
				fgets_retval_check = fgets(str, max_buf, fd);
				if (fgets_retval_check != NULL) {
					len = (int)strlen(str);
					if ((len > 1)) {
						pcs = strtok(str, " ");
						retval = atoi(pcs);
					}
				}
			}
			if (fd != NULL)
				pclose(fd);
		}
	}
	out_get_file_length_or_line_count:
	
	return (long)retval;
}

static void __check_machine_support()
{
	fprintf(stdout, "%s", rldns_main_banner);	
	if (divide_by == 4) {
#if defined(__ARM_ARCH_7__) ||  defined(__ARM_ARCH_7A__) ||  defined(__ARM_ARCH_7R__) ||  defined(__ARM_ARCH_7S__) ||  defined(__ARM_ARCH_7M__)
	    fprintf(stdout, "%s", rldns_on_arm);
#elif defined(__i386__)  || defined(__i486__)  || defined(__i586__)  || defined(__i686__) 
	    fprintf(stdout, "%s", rldns_on_x86);
#endif
	}
	else if(divide_by == 8)
		fprintf(stdout, "%s", rldns_on_x86_64);
	else {
		fprintf(stdout, "%s", rldns_on_unsupported);
		exit(0);
	}	
}

static inline unsigned int find_element(char *seekat, int num)
{
	int i = 0, found;
	
	for (i = 0; i < 20; i++) {
		if ((int)seekat[i] == num) { 
			found = 1;
			goto found_me;
		}
		else
			found = 0;
	}
	found_me:
	
	return found;
}

static inline unsigned int _is_this_valid_a_name(char *a_name)
{
	int j, valid = 1, total_invalid_count = 0, continue_validation = 1, counter_dot = 0, len_a_name = 0;
	/* add thread safety from : http://en.wikipedia.org/wiki/Thread_safety */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&mutex);
	total_invalid_count = sizeof(invalid_chars) / divide_by;
	if (a_name != NULL) {
		len_a_name = (int)strlen(a_name);
		for (j = 0; j < total_invalid_count; j++) {
			if (invalid_chars[j] != NULL) {
				if (strstr(a_name, invalid_chars[j]) != NULL) {
					continue_validation = 0;
					valid = 0;
					break;
				}
			}
		}
		if (valid == 1) {
			for (j = 0; j < (len_a_name - 1); j++) {
				if (a_name[j] == (char)0x2e) 
					counter_dot++;	
			}			
			if (continue_validation == 1) {
				if ((strlen(a_name) < 4) || counter_dot < 1)  
					valid = 0;
			}
		}
	}
	pthread_mutex_unlock(&mutex);
	
	return valid;
}

static inline void _read_zone_file()
{
	DIR  *dir_fd;
	FILE *zone_fd;
	char *full_path, *fgets_res, *trimmed_fget_res = NULL, *retfunc = NULL;
	struct dirent *zone_list;
	int a_count  = 0, cname_count  = 0, mx_count  = 0, ns_count  = 0, current_zone_count  = 0, valid_container = 1;
	char *tmp_pcs = NULL, *tmp_ns = NULL, *tmp_ns_ip = NULL;
	char last_char = (char)0x0;
	boolean valid = _false;
	
        _ret_st_mainstruct_domain_zone = malloc(1000 * sizeof(_st_mainstruct_domain_zone));
	_ret_struct_dns_zone = malloc(1000 * sizeof(_st_zone));
	_ret_struct_a_res = malloc(1000 * sizeof(_st_a_res));
	_ret_struct_cname = malloc(1000 * sizeof(_st_cname));
	_ret_struct_mx = malloc(1000 * sizeof(_st_mx));
	_ret_struct_ns = malloc(1000 * sizeof(_st_ns));
	a_count = 0;
	cname_count = 0;
	mx_count = 0;
	ns_count = 0;
	retfunc = strtok(zones_path, "/");
	if (retfunc == NULL) 
            _msg_terminated_err(no_zonepath);
	dir_fd = opendir(zones_path);	
	if (dir_fd == NULL) 
		_msg_terminated_err(no_zonepath);
	current_zone_count = 0;
	
	while ((zone_list =  readdir(dir_fd))) {
		if (strstr(zone_list->d_name, ".zone") != NULL) {
			full_path = n_malloc(((int)strlen(zone_list->d_name)) + (int)strlen(zones_path) + 1);
			strncat(full_path, trim(zones_path), strlen(zones_path));
			strcat(full_path, "/");
			strncat(full_path, trim(zone_list->d_name), strlen(zone_list->d_name));
			zone_fd = fopen(full_path, "r");
			if (zone_fd != NULL) {
				fgets_res = n_malloc(MAX_ZONE_FILE_LINE_LENGTH);
				while ((fgets(fgets_res, MAX_ZONE_FILE_LINE_LENGTH, zone_fd)) != NULL) {
					valid_container = _check_str_for_invalid_chars_container(fgets_res);
					if (valid_container == 0) 
						_msg_terminated_err(rldns_error_zone);
					trimmed_fget_res = trim(fgets_res);
					if (trimmed_fget_res == NULL) 
						_msg_terminated_err(no_zonepath);
					if (strstr(trimmed_fget_res, "masterzone ") != NULL) {
                                                a_count = 0;
						cname_count = 0;
						mx_count = 0;
						ns_count = 0;
						tmp_pcs = strtok(trimmed_fget_res, " ");
						tmp_pcs = strtok(NULL, " ");
						if (tmp_pcs != NULL) {		
							if (strlen(tmp_pcs) <= MAX_A_LENGTH_ALLOWED) {
								current_zone_count = zone_count;
								_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_a_ip_count = 0;
								_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_cname_count = 0;
								_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_mx_count = 0;
								_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_ns_count = 0;
								last_char = _get_last_char_of_str(tmp_pcs);
								if (last_char == 0x2e) {
									tmp_pcs = _last_replace(tmp_pcs, ".", "");
									last_char = (char)0x0;
								}
								if (strstr(tmp_pcs, "..") != NULL)
									_msg_terminated_err(incorrect_zone_syntax);
								((_ret_st_mainstruct_domain_zone) + current_zone_count)->domain_zone = n_malloc((int)strlen(tmp_pcs));
								((_ret_st_mainstruct_domain_zone) + current_zone_count)->domain_zone = strdup(tmp_pcs);
								((_ret_st_mainstruct_domain_zone) + current_zone_count)->uid = zone_count;
								((_ret_struct_dns_zone) + current_zone_count)->zone_aname = n_malloc((int)strlen(tmp_pcs));	
								((_ret_struct_dns_zone) + current_zone_count)->zone_aname = strdup(tmp_pcs);	
								((_ret_struct_dns_zone) + current_zone_count)->uid = zone_count;	
								((_ret_struct_a_res) + current_zone_count)->uid = zone_count;
								tmp_domain_uid = current_zone_count;
								((_ret_struct_cname) + zone_count)->uid = zone_count;
								((_ret_struct_mx) + zone_count)->uid = zone_count;
								((_ret_struct_ns) + zone_count)->uid = zone_count;
								zone_count++;
							}
						}
					}
					if (strstr(trimmed_fget_res, "Arecord ") != NULL) {
                                                tmp_pcs = strtok(trimmed_fget_res, " ");
						tmp_pcs = strtok(NULL, " ");
						if (strstr(tmp_pcs, "..") != NULL)
							_msg_terminated_err(incorrect_zone_syntax);
						_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_a_ip_count++;
						a_count++;
						if ((tmp_pcs != NULL) && sizeof(tmp_pcs) >= divide_by) {	
							if ((strlen(tmp_pcs) > 0) && (strlen(tmp_pcs) <= MAX_IP_LENGTH)) {	 	
								valid = validate_ipv4_octet(tmp_pcs);
								if (valid == _true) {
                                                                    ((_ret_struct_a_res) + current_zone_count)->a_ip[a_count] = n_malloc((int)strlen(tmp_pcs));
                                                                    ((_ret_struct_a_res) + current_zone_count)->a_ip[a_count] = strdup(tmp_pcs);
                                                                }
								else
                                                                    a_count--;
							}	
						}								
						if (a_count > 18)
							_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_a_ip_count = 18;
					}
					if (strstr(trimmed_fget_res, "CNAMErecord ") != NULL) {
                                                tmp_pcs = strtok(trimmed_fget_res, " ");
						tmp_pcs = strtok(NULL, " ");
						last_char = _get_last_char_of_str(tmp_pcs);
						if (last_char == 0x2e) {
							tmp_pcs = _last_replace(tmp_pcs, ".", "");
							last_char = (char)0x0;
						}
						if (strstr(tmp_pcs, "..") != NULL)
							_msg_terminated_err(incorrect_zone_syntax);
						cname_count++;
						if ((tmp_pcs != NULL) && sizeof(tmp_pcs) >= divide_by) {	
							if ((strlen(tmp_pcs) > 0) && (strlen(tmp_pcs) <= MAX_CNAME_LENGTH)) {		
								((_ret_struct_cname) + current_zone_count)->cname[cname_count] = n_malloc((int)strlen(tmp_pcs));
								((_ret_struct_cname) + current_zone_count)->cname[cname_count] = strdup(tmp_pcs);
							}	
							else
								cname_count--;
						}								
						else
							cname_count--;
						_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_cname_count = cname_count;	
					}
					if (strstr(trimmed_fget_res, "MXrecord ") != NULL) {
						tmp_pcs = strtok(trimmed_fget_res, " ");
						tmp_pcs = strtok(NULL, " ");
                                        	last_char = _get_last_char_of_str(tmp_pcs);
						if (last_char == 0x2e) {
							tmp_pcs = _last_replace(tmp_pcs, ".", "");
							last_char = (char)0x0;
						}
						if (strstr(tmp_pcs, "..") != NULL)
							_msg_terminated_err(incorrect_zone_syntax);
						if (tmp_pcs != NULL) {	
							if (strlen(tmp_pcs) > MAX_MX_LENGTH) {
								((_ret_struct_mx) + current_zone_count)->mx_host = n_malloc(MAX_MX_LENGTH);
								((_ret_struct_mx) + current_zone_count)->mx_host = strndup(tmp_pcs, MAX_MX_LENGTH);
							}
							else {
								((_ret_struct_mx) + current_zone_count)->mx_host = n_malloc((int)strlen(tmp_pcs));
								((_ret_struct_mx) + current_zone_count)->mx_host = strndup(tmp_pcs, strlen(tmp_pcs));
							}
                                               }
						else 
							mx_count--;
						tmp_pcs = strtok(NULL, " ");
						//fprintf(stdout, "mx found : %s", ((_ret_struct_mx) + current_zone_count)->mx_host);
						_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_mx_count = mx_count;	
					}
					if (strstr(trimmed_fget_res, "NSrecord ") != NULL) {
						tmp_pcs = strtok(trimmed_fget_res, " ");
						tmp_pcs = strtok(NULL, " ");
						last_char = _get_last_char_of_str(tmp_pcs);
						if (last_char == (char)0x2e) {
							tmp_pcs = _last_replace(tmp_pcs, ".", "");
							last_char = (char)0x0;
						}
						if (strstr(tmp_pcs, "..") != NULL)
							_msg_terminated_err(incorrect_zone_syntax);
						if (tmp_pcs != NULL)
							tmp_ns = tmp_pcs;
						tmp_pcs = strtok(NULL, " ");
						if (tmp_pcs != NULL)
							tmp_ns_ip = tmp_pcs;
						ns_count++;
						if (tmp_ns != NULL) {	
                                                       if (strlen(tmp_ns) > MAX_NS_LENGTH) {
								((_ret_struct_ns) + current_zone_count)->ns[ns_count] = n_malloc(MAX_NS_LENGTH);	
								((_ret_struct_ns) + current_zone_count)->ns[ns_count] = strndup(tmp_ns, MAX_NS_LENGTH);

							}
							else {	
								((_ret_struct_ns) + current_zone_count)->ns[ns_count] = n_malloc((int)strlen(tmp_ns));	
								((_ret_struct_ns) + current_zone_count)->ns[ns_count] = strdup(tmp_ns);
							}
							if (tmp_ns_ip != NULL) {	
								if (strlen(tmp_ns_ip) > 16 /* ip v4 support only */) {
									((_ret_struct_ns) + current_zone_count)->ns_ip[ns_count] = n_malloc(16);	
									((_ret_struct_ns) + current_zone_count)->ns_ip[ns_count] = strndup(tmp_ns_ip, 16);

								}
								else {	
									((_ret_struct_ns) + current_zone_count)->ns_ip[ns_count] = n_malloc((int)strlen(tmp_ns_ip));	
									((_ret_struct_ns) + current_zone_count)->ns_ip[ns_count] = strdup(tmp_ns_ip);
								}
							}
						}
						else 
							ns_count--;
						_ret_st_mainstruct_domain_zone[current_zone_count].domain_zone_ns_count = ns_count;
					}
				}
			}
		}
	}
}

static inline char *parse_enumerate_and_fetch_each_octet_and_just_return_a_name(char *msg, int receive_len)
{
	int i, j, possible_first_octet_length = 0, possible_second_octet_length = 0, possible_third_octet_length = 0, possible_fourth_octet_length = 0, is_special_tld = 0, x = 0;
	int match = 0, _count_final_offset = 0, start_offset = 0, second_offset = 0, third_offset = 0, fourth_offset = 0, total_offset = 0, retfunc = 0; 
	char *_final_name = NULL, *_name = NULL;
	char *first_octet = NULL;
	char *second_octet = NULL;
	char *third_octet = NULL;
	char  *fourth_octet = NULL;
	char *_tmp_aname = NULL, *_tmp_cname = NULL;
	int count_len = 0;
	
	if (msg == NULL) return NULL;
	if (receive_len < 12) return NULL;
	possible_first_octet_length = (int)msg[12];
	if (possible_first_octet_length < -1) return NULL;
	if (12 + possible_first_octet_length + 1 > receive_len) return NULL;
   	possible_second_octet_length = (int)msg[12 + possible_first_octet_length + 1];
	if (possible_second_octet_length < -1) return NULL;
	possible_third_octet_length = (int)msg[12 + possible_first_octet_length + possible_second_octet_length + 2];
	if (possible_third_octet_length < -1) return NULL;
	possible_fourth_octet_length = (int)msg[12 + possible_first_octet_length + possible_second_octet_length + possible_third_octet_length + 3];
	if (possible_fourth_octet_length < -1) return NULL;
	total_offset = possible_first_octet_length + possible_second_octet_length + possible_third_octet_length + possible_fourth_octet_length + 4;
	_name = n_malloc(total_offset + 1);
	if (_name == NULL) return NULL;
	_name[total_offset] = '\0';
	if (possible_first_octet_length > 0) {
		start_offset = 12;
		j = 0;
		first_octet = n_malloc(possible_first_octet_length);
		for(i = 1; i < possible_first_octet_length; i++)  {
			if (x < total_offset) {
				_name[x] = msg[start_offset + i]; 
				first_octet[j] = msg[start_offset + i];
				x++;
				j++;
			}
		}
	}
	if (possible_second_octet_length > 0) {	
		_name[x++] = '.';
		j = 0;
		second_octet = n_malloc(possible_second_octet_length);
		second_offset = 12 + possible_first_octet_length + 1;	
		for(i = 1; i < possible_second_octet_length; i++) {
			if (x < total_offset) {
				_name[x]  = msg[second_offset + i];
				second_octet[j] = msg[second_offset + i];
				j++;
				x++;
			}
		}
	}
	if (possible_third_octet_length > 0) {
		_name[x++] = '.';
		j = 0;
		third_offset = 12 + possible_first_octet_length + possible_second_octet_length + 2;
		third_octet = n_malloc(possible_third_octet_length);
		for(i = 1; i < possible_third_octet_length; i++) {
			if (x < total_offset) {
				_name[x]  = msg[third_offset + i];
				third_octet[j] = msg[third_offset + i];
				j++;
				x++;
			}
		}
	}
	if (possible_fourth_octet_length > 0) {
		j = 0;
		_name[x++] = '.';
		fourth_offset = 12 + possible_first_octet_length + possible_second_octet_length + possible_third_octet_length + 3;
		fourth_octet = n_malloc(possible_fourth_octet_length);
		for(i = 1; i < possible_fourth_octet_length; i++) {
			if (x < total_offset) {
				_name[x]  = msg[fourth_offset + i];
				fourth_octet[j] = msg[fourth_offset + i];
				j++;
				x++;
			}
		}
	}
	_count_final_offset = _count_octet_length(_name);
	if (_count_final_offset == 1) {
		match = 1;
		_final_name = n_malloc((int)strlen(_name) + 1);
		count_len = (int)strlen(_name) + 1;
		#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
		strlcpy(_final_name, _name, (size_t)count_len);
		#else
		strncpy(_final_name, _name, (size_t)count_len);
		#endif
		goto final;
	}
	else {
		for (j = 0; j < (sizeof(special_tld) / divide_by); j++) {
			//if (strstr(_name, special_tld[j]) != NULL) 
			if (memmem(_name, count_len, special_tld[j], strlen(special_tld[j])) != NULL)
				is_special_tld = 1;
		}	
		if (is_special_tld == 1) {
			/** processing request with special tld **/	
			if (_count_final_offset == 3) {
				generic_full_a_name_requested = n_malloc(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + possible_first_octet_length + 5);
				_tmp_aname = n_malloc(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + 4);
				snprintf(generic_full_a_name_requested, (size_t)(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + possible_first_octet_length + 4) ,"%s.%s.%s.%s", first_octet, second_octet, third_octet, fourth_octet);
				retfunc = snprintf(_tmp_aname, (size_t)(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + 3) ,"%s.%s.%s", second_octet, third_octet, fourth_octet);
				if (retfunc <= 0)
					goto final;
				match = _enumerate_cname_at_zone(first_octet, _tmp_aname);
				if (match == 1) {
					_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
					count_len = (int)strlen(_tmp_aname) + 1;
					#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
					strlcpy(_final_name, _tmp_aname,  (size_t)count_len);
					#else
					strncpy(_final_name, _tmp_aname, (size_t)count_len);
					#endif
				}
				else {	
					match = _enumerate_octet_at_ns_zone(first_octet, _tmp_aname, rldns_response_id);
					if (match == 1) {
						_final_name = n_malloc((int)strlen((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name) + 1);
						count_len = (int)strlen((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name) + 1;
						#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
						strlcpy(_final_name, (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name, (size_t)count_len);		
						#else
						strncpy(_final_name, (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name, (size_t)count_len);		
						#endif
					}
				}
			}
			else if (_count_final_offset == 2) {
				_tmp_aname = n_malloc(possible_third_octet_length + possible_second_octet_length  + possible_first_octet_length + 4);
				retfunc = snprintf(_tmp_aname, (size_t)(possible_third_octet_length + possible_second_octet_length  + possible_first_octet_length + 3), "%s.%s.%s", first_octet, second_octet, third_octet);
				if (retfunc <= 0)
					goto final;
				match = 0;
				match = _enumerate_octet_at_ns_zone(first_octet, _tmp_aname, rldns_response_id);
				if (match == 1) {
					_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
					count_len = (int)strlen(_tmp_aname) + 1;
					#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
					strlcpy(_final_name, _tmp_aname, (size_t)count_len);
					#else
					strncpy(_final_name, _tmp_aname, (size_t)count_len);
					#endif
				}
				else {
					match = 1;
					_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
					count_len = (int)strlen(_tmp_aname) + 1;
					#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
					strlcpy(_final_name, _tmp_aname, (size_t)count_len);
					#else
					strncpy(_final_name, _tmp_aname, (size_t)count_len);
					#endif
				}	
			}
		}
		else {
			/* processing request without special tld */	
			if (_count_final_offset == 3) {
				_tmp_aname = n_malloc(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + 2);
				retfunc = snprintf(_tmp_aname, (size_t)(possible_fourth_octet_length + possible_third_octet_length + possible_second_octet_length + 2) ,"%s.%s", third_octet, fourth_octet);
				if (retfunc <= 0)
					goto final;
				match = 0;
				_tmp_cname = n_malloc(possible_first_octet_length + possible_second_octet_length + 1);
				retfunc = snprintf(_tmp_cname , (size_t)(possible_first_octet_length + possible_second_octet_length + 1), "%s.%s", first_octet, second_octet);
				if (retfunc <= 0)
					goto final;
				match = _enumerate_cname_at_zone(_tmp_cname, _tmp_aname);
				if (match == 1) {
					_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
					count_len = (int)strlen(_tmp_aname) + 1;
					#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
					strlcpy(_final_name, _tmp_aname, (size_t)count_len);
					#else
					strncpy(_final_name, _tmp_aname, (size_t)count_len);
					#endif		
				}
				else {	
					match = _enumerate_octet_at_ns_zone(_tmp_cname, _tmp_aname, rldns_response_id);
					if (match == 1) {
						_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
						count_len = (int)strlen(_tmp_aname) + 1;
						#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
						strlcpy(_final_name, _tmp_aname, (size_t)count_len);
						#else
						strncpy(_final_name, _tmp_aname, (size_t)count_len);
						#endif
					}
				}
			}
			else if (_count_final_offset == 2) {
				_tmp_aname = n_malloc(possible_third_octet_length + possible_second_octet_length  + 2); 
				if (second_octet != NULL && third_octet != NULL) {
					retfunc = snprintf(_tmp_aname, (size_t)(possible_third_octet_length + possible_second_octet_length  + 2),"%s.%s", second_octet, third_octet);
					if (retfunc <= 0)
						goto final;
					match = 0;
					match = _enumerate_cname_at_zone(first_octet, _tmp_aname);
					if (match == 1)  {
						_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
						count_len = (int)strlen(_tmp_aname) + 1;
						#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
						strlcpy(_final_name, _tmp_aname, (size_t)count_len);
						#else
						strncpy(_final_name, _tmp_aname, (size_t)count_len);
						#endif
					}	
					else {	
						match = _enumerate_octet_at_ns_zone(first_octet, _tmp_aname, rldns_response_id);
						if (match == 1) {
							_final_name = n_malloc((int)strlen(_tmp_aname) + 1);
							count_len = (int)strlen(_tmp_aname) + 1;
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(_final_name, _tmp_aname, (size_t)count_len);
							#else
							strncpy(_final_name, _tmp_aname, (size_t)count_len);
							#endif
						}
					}
				}
				else {
					match = 0;
					goto final;
				}
			}
		}	
	}
	final:
	if (match != 1) {
		generic_answer_type = RET_NO_ANSWER; 
		_final_name = RET_NO_ANSWER;
	}
	
	return _final_name;
}

static inline unsigned int _enumerate_octet_at_ns_zone(char *_octet_str, char *_tmp_aname, int rldns_response_id)
{
	int i, match = 0, count_len = 0;
	
	if ((_tmp_aname != NULL) && (sizeof(_tmp_aname) >= divide_by)) {
		for (i = 1; i < zone_count; i++) {
			if (strcmp(((_ret_struct_dns_zone) + i)->zone_aname, _tmp_aname) == 0) {
				(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name  = n_malloc((int)strlen(_tmp_aname));
				(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name  = strndup(_tmp_aname, strlen(_tmp_aname));
				if (((_ret_struct_ns) + i)->ns[1] != NULL) {
					if (strcmp(((_ret_struct_ns) + i)->ns[1], _octet_str) == 0) { 
						match = 1;
						if ((((_ret_struct_ns) + i)->ns_ip[1] != NULL) && (sizeof(((_ret_struct_ns) + i)->ns_ip[1]) >= divide_by)) {
							if (strlen(((_ret_struct_ns) + i)->ns_ip[1]) <= 16) {
								(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip = n_malloc((int)strlen(((_ret_struct_ns) + i)->ns_ip[1]));
								count_len = (int)strlen(((_ret_struct_ns) + i)->ns_ip[1]);
								#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
								strlcpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[1], (size_t)count_len);
								#else
								strncpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[1], (size_t) count_len);
								#endif	
								generic_answer_type = RET_NS_IP;	
							}
						}
						break;
					}
				}
				if (((_ret_struct_ns) + i)->ns[2] != NULL) {
					if (strcmp(((_ret_struct_ns) + i)->ns[2], _octet_str) == 0) { 
						match = 1;
						if ((((_ret_struct_ns) + i)->ns_ip[2] != NULL) && (sizeof(((_ret_struct_ns) + i)->ns_ip[2]) >= divide_by)) {
							if (strlen(((_ret_struct_ns) + i)->ns_ip[2]) <= 16) {
								(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip = n_malloc(strlen(((_ret_struct_ns) + i)->ns_ip[2]));
								count_len = (int)strlen(((_ret_struct_ns) + i)->ns_ip[2]);
								#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
								strlcpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[2], (size_t)count_len);
								#else
								strncpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[2], (size_t)count_len);
								#endif	
								generic_answer_type = RET_NS_IP;	
							}
						}
						break;
					}
				}	
				if (((_ret_struct_ns) + i)->ns[3] != NULL) {
					if (strcmp(((_ret_struct_ns) + i)->ns[3], _octet_str) == 0) { 
						match = 1;
						if ((((_ret_struct_ns) + i)->ns_ip[3] != NULL) && (sizeof(((_ret_struct_ns) + i)->ns_ip[3]) >= divide_by)) {
							if (strlen(((_ret_struct_ns) + i)->ns_ip[3]) <= 16) {
								(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip = n_malloc(strlen(((_ret_struct_ns) + i)->ns_ip[3]));
								count_len = (int)strlen(((_ret_struct_ns) + i)->ns_ip[3]);
								#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
								strlcpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[3], (size_t)count_len);
								#else
								strncpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[3], (size_t)count_len);
								#endif	
								generic_answer_type = RET_NS_IP;	
							}
						}
						break;
					}
				}	
				if (((_ret_struct_ns) + i)->ns[4] != NULL) {
					if (strcmp(((_ret_struct_ns) + i)->ns[4], _octet_str) == 0) { 
						match = 1;
						if ((((_ret_struct_ns) + i)->ns_ip[4] != NULL) && (sizeof(((_ret_struct_ns) + i)->ns_ip[4]) >= divide_by)) {
							if (strlen(((_ret_struct_ns) + i)->ns_ip[4]) <= 16) {
								(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip = n_malloc(strlen(((_ret_struct_ns) + i)->ns_ip[4]));
								count_len = (int)strlen(((_ret_struct_ns) + i)->ns_ip[4]);
								#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
								strlcpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[4], (size_t)count_len);
								#else
								strncpy((_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip, ((_ret_struct_ns) + i)->ns_ip[4], (size_t)count_len);
								#endif	
								generic_answer_type = RET_NS_IP;	
							}
						}
						break;
					}
				}	
			}
			else
				(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_a_name = NULL;
		}
	}
	
	return match;
}

/** continue cname processing !!! **/
static inline unsigned int _enumerate_cname_at_zone(char *_cname, char *_tmp_aname)
{
	int i , match = 0;

	for (i = 0; i < zone_count; i++) {
		if (strcmp(((_ret_struct_dns_zone) + i)->zone_aname, _tmp_aname) == 0) {
			if ((sizeof((_ret_struct_cname + i )->cname[1]) >= divide_by) && ((_ret_struct_cname + i )->cname[1] != NULL)) {
				if (strcmp((_ret_struct_cname + i )->cname[1], _cname) == 0) { 
					match = 1;
					goto out;
				}
			}
			if ((sizeof((_ret_struct_cname + i )->cname[2]) >= divide_by) && ((_ret_struct_cname + i )->cname[2] != NULL)) {
				if (strcmp((_ret_struct_cname + i )->cname[2], _cname) == 0) { 
					match = 1;
					goto out;
				}
			}
			if ((sizeof((_ret_struct_cname + i )->cname[3]) >= divide_by) && ((_ret_struct_cname + i )->cname[3] != NULL)) {
				if (strcmp((_ret_struct_cname + i )->cname[3], _cname) == 0) { 
					match = 1;
					goto out;
				}
			}
			if ((sizeof((_ret_struct_cname + i )->cname[4]) >= divide_by) && ((_ret_struct_cname + i )->cname[4] != NULL)) {
				if (strcmp((_ret_struct_cname + i )->cname[4], _cname) == 0) { 
					match = 1;
					goto out;
				}
			}
			if ((sizeof((_ret_struct_cname + i )->cname[5]) >= divide_by) && ((_ret_struct_cname + i )->cname[5] != NULL)) {
				if (strcmp((_ret_struct_cname + i )->cname[5], _cname) == 0) { 
					match = 1;
					goto out;
				}
			}
		}
	}					
	out:
	
	return match;
}

static inline char *determine_dns_request_type(char *request)
{
	char *return_request_type;
	int i = 0, octet = 0;

	for (i = header_length; i <= MAX_A_LENGTH_ALLOWED; i++) {
		if ((int)request[i] == 0) 
			break;
	}
	i+= 2;
	if ((unsigned)(unsigned char)request[i] == 0xf) {
		if (generic_full_a_name_requested != NULL) 
			octet = _count_octet_length(generic_full_a_name_requested);
		if (octet > 2)
			return_request_type = "A";
		else
			return_request_type = "mx";
	}
	else if ((unsigned)(unsigned char)request[i] == 0x2) { 
		if (generic_full_a_name_requested != NULL) 
			octet = _count_octet_length(generic_full_a_name_requested);
		if (octet > 2)
			return_request_type = "A";
		else
			return_request_type = "ns";
	}
	else if ((unsigned)(unsigned char)request[i] == 0x1) 
		return_request_type = "A";
	else 
		return_request_type = "A";
	if (return_request_type == NULL)
		return_request_type = "A";
	if (generic_full_a_name_requested != NULL) 
		generic_full_a_name_requested = NULL;
	
	return return_request_type;
}

static inline unsigned int analyze_invalid_dns_request(char *dns_packet, int receive)
{
	int a_length = 0, valid = 1;
	
	if ((dns_packet == NULL) || (sizeof(dns_packet) < divide_by )) 
		valid = 0;
	else if ((dns_packet[13] == '\x00') || (dns_packet[13] == '\0')) 
		valid = 0;
	else if (((int)dns_packet[12] > MAX_A_LENGTH_ALLOWED) || (int)dns_packet[12] <= 1) 
		valid = 0;
	else {		
		a_length = parse_enumerate_each_octet_and_count_length(dns_packet, receive);
		if (a_length <= 0) 
			valid = 0;
	}
	
	return valid;
}

static inline unsigned int _count_octet_length(char *a_name)
{
	int i  = 0, _count = 0;
	
	if (a_name != NULL) {
		for (i = 0;i  < (int)strlen(a_name); i++)  {
			if (a_name[i] == '.')
				_count++;	
		}
	}
	
	return _count;
}

int daemonize()
{
	pid_t worker_pid;
	
	worker_pid = fork();
	if (worker_pid != 0) 
		exit(0);
	
	return 0;
}

static inline char *_do_fetch_self_ns(char *full_ns) {
	char *the_ns = '\0';
	char *piece = NULL;
	
	piece = strtok(full_ns, ".");
	if (piece != NULL) 
		the_ns = piece;

	return the_ns;	
}

static inline char *_last_replace(char *original_str, char *str_to_replace, char *replacer_str)
{
	char *clean_str;
	int i, z, half_done, len_original_str, len_str_to_replace, len_replacer_str, len_clean_str;
	
	len_original_str = (int)strlen(original_str);
	len_str_to_replace = (int)strlen(str_to_replace);
	i = 0;
	if (replacer_str == NULL) {
		len_clean_str = len_original_str - len_str_to_replace;
		clean_str = n_malloc(len_clean_str);
		for (i = 0; i < len_clean_str; i++) 
			clean_str[i] = original_str[i];
	}
	else {
		len_replacer_str = (int)strlen(replacer_str);
		half_done = len_original_str - len_str_to_replace;
		len_clean_str = (len_original_str - len_str_to_replace) + len_replacer_str;
		clean_str = n_malloc(len_clean_str);
		for (i = 0; i < half_done; i++) 
			clean_str[i] = original_str[i];
		z = 0;
		for (i = half_done; i < len_clean_str;i++) {
			clean_str[i] = replacer_str[z];
			z++;
		}	
	}

	return clean_str;
}

static inline char _get_last_char_of_str(char *checkme)
{
	char retme = '\0';
	int str_size;
	
	if (checkme != NULL) {	
		str_size = ((int)strlen(checkme)) - 1;	
		retme = checkme[str_size];
	}
	
	return retme;
}

static inline char *n_malloc(int size) 
{
	char *retme = NULL;
	
	if (size > 0) {
		retme = malloc((size_t)(size + 1));
		if (retme != NULL)
			memset(retme, (int)'\0', (size_t)(size + 1));
	}
	if (retme == NULL)
		return (char *)'\0';
	
	return retme;
}

static inline void _msg_err(char *msg)
{
	fprintf(stdout, "%s", msg);
	syslog(LOG_DAEMON, "%s", msg);	
}

static inline  void _msg_terminated_err(char *msg)
{
	fprintf(stdout, "%s", msg);
	syslog(LOG_DAEMON, "%s", msg);
	exit(0);
}

static void _check_config()
{
	struct stat buf;
        
        chdir(rldns_path);
	if (stat("rldns.conf", &buf) == 0)
		printf("\t[+] found configuration file : rldns.conf \n");	
	else 
            _msg_terminated_err(no_config);
}

static int fcntl_nonblock(int sock_fd)
{
	/* add thread safety from : http://en.wikipedia.org/wiki/Thread_safety */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&mutex);
 	if (fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFD, 0) | O_NONBLOCK) == -1) {
		_msg_err(fail_nonblock);
		return -1;
	}
	pthread_mutex_unlock(&mutex);
 
	return sock_fd;
}

static _st_configurations *_init_read_parse_config()
{
	_st_configurations *rldns_config;
	char *result = NULL;
	FILE *config;
	int total_line  = 0, len, cur_line = 0;
	char str[256] = "\0";
	int offset_dns1  = 0, offset_dns2  = 0, struct_offset = 0, offset_port  = 0, offset_worker  = 0, offset_version  = 0, offset_zones = 0, offset_resolver_type = 0, retfunc = 0, valid_container = 1;
	int len_recursive_dns1 = 0, len_recursive_dns2 = 0, len_version = 0, len_zones = 0;
	
	rldns_config = malloc(1 * sizeof(_st_configurations));
	fprintf(stdout, "\t[+] reading rldns configuration file\n");
	config = fopen(CONFIG, "r");
	if (config != NULL) {
		total_line = (int)get_file_length_or_line_count(CONFIG, "line");
		while((fgets(str, max_buf, config) != NULL) && (cur_line <= total_line)) {
			len = (int)strlen(str);
			if (len > 1)
				if (!strstr(str, ";")) {
					result = strtok(str, " ");
					while(result != NULL) {
					/**	fillin the configuration struct **/
						valid_container = _check_str_for_invalid_chars_container(result);
						if (valid_container == 0) 
							_msg_terminated_err(rldns_error_config);
						if (offset_dns1 == 1) {
							(rldns_config + struct_offset)->dns1 =  n_malloc((int)strlen(result));
							(rldns_config + struct_offset)->dns1 = result;
							recursive_dns1 =  n_malloc((int)strlen((rldns_config + struct_offset)->dns1));
							len_recursive_dns1 = (int)strlen((rldns_config + struct_offset)->dns1);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(recursive_dns1, (rldns_config + struct_offset)->dns1, (size_t)len_recursive_dns1);
							#else
							strncpy(recursive_dns1, (rldns_config + struct_offset)->dns1, (size_t)len_recursive_dns1);
							#endif
						}
						if (offset_dns2 == 1) {
							(rldns_config + struct_offset)->dns2 =  n_malloc((int)strlen(result));
							(rldns_config + struct_offset)->dns2 = trim(result);
							recursive_dns2 =  n_malloc((int)strlen((rldns_config + struct_offset)->dns2));
							len_recursive_dns2 = (int)strlen((rldns_config + struct_offset)->dns2);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(recursive_dns2, (rldns_config + struct_offset)->dns2, (size_t)len_recursive_dns2);
							#else
							strncpy(recursive_dns2, (rldns_config + struct_offset)->dns2, (size_t)len_recursive_dns2);
							#endif
						}
						if (offset_version == 1) {
							(rldns_config + struct_offset)->version =  n_malloc((int)strlen(result));
							(rldns_config + struct_offset)->version = trim(result);
							version =  n_malloc((int)strlen((rldns_config + struct_offset)->version));
							len_version = strlen((rldns_config + struct_offset)->version);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(version, (rldns_config + struct_offset)->version, (size_t)len_version);
							#else
							strncpy(version, (rldns_config + struct_offset)->version, (size_t)len_version);
							#endif
							fprintf(stdout, "\t[+] rldns version : %s\n", (rldns_config + struct_offset)->version);
						}
						if (offset_zones == 1) {
							(rldns_config + struct_offset)->zones =  n_malloc((int)strlen(result));
							(rldns_config + struct_offset)->zones = trim(result);
							zones_path =  n_malloc((int)strlen((rldns_config + struct_offset)->zones));
							len_zones = strlen((rldns_config + struct_offset)->zones);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(zones_path, (rldns_config + struct_offset)->zones, (size_t)len_zones);
							#else
							strncpy(zones_path, (rldns_config + struct_offset)->zones, (size_t)len_zones);
							#endif
							fprintf(stdout, "\t[+] rldns zone(s) : %s\n",(rldns_config + struct_offset)->zones);
						}
						if (offset_port == 1) {
							(rldns_config + struct_offset)->port = atoi(result);
							rldns_port = (rldns_config + struct_offset)->port;
							fprintf(stdout, "\t[+] rldns port : %d\n", (rldns_config + struct_offset)->port);
						}
						if (offset_worker == 1) {
							(rldns_config + struct_offset)->worker = atoi(result);
							worker = (rldns_config + struct_offset)->worker;
							fprintf(stdout, "\t[+] rldns worker(s) : %d\n", (rldns_config + struct_offset)->worker);
						}
						if (offset_resolver_type == 1) {
							(rldns_config + struct_offset)->resolver_type = atoi(result);
							resolver_type = (rldns_config + struct_offset)->resolver_type;
							fprintf(stdout, "\t[+] rldns resolver type : %d\n", (rldns_config + struct_offset)->resolver_type);
						}
						if (strcmp(result, "port") == 0) 
							offset_port = 1;
						else
							offset_port = 0;
						if (strcmp(result, "worker") == 0) 
							offset_worker = 1;
						else
							offset_worker = 0;
						if (strcmp(result, "version") == 0) 
							offset_version = 1;
						else
							offset_version = 0;
						if (strcmp(result, "zones") == 0) 
							offset_zones = 1;
						else
							offset_zones = 0;
						if (strcmp(result, "dns1") == 0)
							offset_dns1 = 1;
						else 
							offset_dns1 = 0;
						if (strcmp(result, "dns2") == 0)
							offset_dns2 = 1;
						else
							offset_dns2 = 0;	
						if (strcmp(result, "resolvertype") == 0) 
							offset_resolver_type = 1;
						else
							offset_resolver_type = 0;
						result = strtok(NULL, " ");
					}	
				}		
			cur_line++;
		}
	}	
	else
		_msg_terminated_err(no_config);
	if (config != NULL) {
		retfunc = fclose(config);
		if (retfunc != 0)
			_msg_err(fail_to_closefd);
	}
	if (rldns_config == NULL)
		_msg_terminated_err(no_config);	
	
	return rldns_config;
}

/* 
developing this function in 4 minutes only at 1:22pm feb 20 2014
*/
static inline unsigned int _check_str_for_invalid_chars_container(char *str_to_check)
{
	int _tot_invalid_count = 0, examine, ret_val_res = 1;

	/* divide_by depends on processor */	
	if (str_to_check != NULL) {	
		_tot_invalid_count = sizeof(invalid_conf_and_zone_chars) / divide_by;
		for (examine = 0; examine < _tot_invalid_count; examine++) {
			if (invalid_conf_and_zone_chars[examine] != NULL) {
				if (strstr(str_to_check, invalid_conf_and_zone_chars[examine]) != NULL) {
					ret_val_res = 0;
					break;
				}
			}
		}
	}
	
	return ret_val_res;
}

static inline unsigned int parse_enumerate_each_octet_and_count_length(char *msg, int receive)
{
	int a_length = 0;
	int possible_first_octet_length, possible_second_octet_length, possible_third_octet_length, possible_fourth_octet_length;
	char *qname = NULL;

	qname = parse_enumerate_and_fetch_each_octet_and_just_return_a_name(msg, receive);
	if (qname == NULL) {
		return 0;
	}
	possible_first_octet_length = (int)msg[12];
	possible_second_octet_length = (int)msg[12 + possible_first_octet_length + 1];
	possible_third_octet_length = (int)msg[12 + possible_first_octet_length + possible_second_octet_length + 2];
	possible_fourth_octet_length = (int)msg[12 + possible_first_octet_length + possible_second_octet_length + possible_third_octet_length + 3];
	/** fetch first octet **/
	if (possible_first_octet_length > 0) 
		a_length += possible_first_octet_length;
	if (possible_second_octet_length > 0) 
		a_length += (possible_second_octet_length + 1);
	if (possible_third_octet_length > 0) 
		a_length += (possible_third_octet_length +1);
	if (possible_fourth_octet_length > 0) 
		a_length += (possible_fourth_octet_length + 1);
	
	return a_length;
}

static inline boolean validate_ipv4_octet(char *ipaddr)
{
	int j, octet_found = 0;
	boolean valid = _false;
	
	if ((sizeof(ipaddr) > 0) && ipaddr[0] != '\0') {
		if ((strlen(ipaddr) > 0) && (strlen(ipaddr) <= MAX_IP_LENGTH)) {
			for (j = 0; j < (int)(strlen(ipaddr)); j++) {
				if (ipaddr[j] == (char)0x2e) 
					octet_found++;
			}
			if (octet_found == 3 /* ip v4 address only */) 
				valid = _true;
		}
	}
	else
		valid = _false;
	
	return valid;
}

static inline char *get_current_dns_qid(char *msg)
{
	char *qid;
	
	qid = n_malloc(2);
	qid[0] = msg[0];
	qid[1] = msg[1];

	return qid;
}

static inline void __send_udp_packet_and_get_teh_reply(char *dns_packet)
{
	/* add thread safety from : http://en.wikipedia.org/wiki/Thread_safety */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
 	struct hostent *shost;
	int i, _len_ns = 0, rcv  = 0, len  = 0,  __udp_sock =  socket(AF_INET, SOCK_DGRAM, 0), new_fd = 0, sendto_ret;
	boolean valid_ip = _false;
	char *__dns = NULL, *_dns_ip = NULL, *_retme;
	char buffer[PACKET_SIZE];
	struct timeval timeout_udp;
	fd_set selectfds2;
	
	pthread_mutex_lock(&mutex);
 	new_fd = dup(rldns_sock);
	timeout_udp.tv_sec = 5;
	timeout_udp.tv_usec = 100000;
	__udp_sock = fcntl_nonblock(__udp_sock);
	if (__udp_sock == -1) 
		goto _get_out_of_here_its_gonna_blow;
	setsockopt(__udp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout_udp, sizeof(timeout_udp));
	setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout_udp, sizeof(timeout_udp));
	if (recursive_dns1 != NULL) {
		if (sizeof(recursive_dns1) > 0) {
			_len_ns = (int)strlen(recursive_dns1);
			__dns = n_malloc(_len_ns);
			#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
			strlcpy(__dns, recursive_dns1, (size_t)_len_ns);
			#else
			strncpy(__dns, recursive_dns1, (size_t)_len_ns);
			#endif
		}
	}
	if ((recursive_dns2 != NULL) && _len_ns < 1) {
		_len_ns = (int)strlen(recursive_dns2);
		__dns = n_malloc(_len_ns);
		#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
		strlcpy(__dns, recursive_dns2, (size_t)_len_ns);
		#else
		strncpy(__dns, recursive_dns2, (size_t)_len_ns);
		#endif
	}
	if (strlen(__dns) > 1) {
		valid_ip =  validate_ipv4_octet(__dns);
		if (valid_ip == _false) {
			shost = gethostbyname2(__dns, AF_INET); 
			if (shost == NULL)
				goto _get_out_of_here_its_gonna_blow;
			if (shost->h_addr) {
				_dns_ip = n_malloc((int)strlen(shost->h_addr));
				#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
				strlcpy(_dns_ip, shost->h_addr, strlen(shost->h_addr));
				#else
				strncpy(_dns_ip, shost->h_addr, strlen(shost->h_addr));
				#endif
			}				
		}
		else {
			_dns_ip = n_malloc((int)strlen(__dns));
			#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
			strlcpy(_dns_ip, __dns, strlen(_dns_ip));
			#else
			strncpy(_dns_ip, __dns, strlen(__dns));
			#endif			
		}
		bzero(&server_addr, sizeof(len));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr(_dns_ip);
		server_addr.sin_port = htons(recursive_dns_port);
		len = (int)sizeof(server_addr);
		bzero(buffer, sizeof(buffer));
		for (i = 0; i < PACKET_SIZE; i++) 
			buffer[i] = dns_packet[i];
		sendto_ret = sendto(__udp_sock, buffer, sizeof(buffer), 0, (const struct sockaddr *)&server_addr, len);
		if (sendto_ret == -1)
			goto _get_out_of_here_its_gonna_blow;
		for (;;) {
			timeout_udp.tv_sec = 5;
			timeout_udp.tv_usec = 100000;
			usleep(7777);
			FD_ZERO(&selectfds2);
			FD_SET(__udp_sock, &selectfds2);
			if (select(sizeof(selectfds2) * divide_by, &selectfds2, NULL, NULL, &timeout_udp) == 0) 
				goto _get_out_of_here_its_gonna_blow;
			else {
				bzero(buffer, sizeof(buffer));
				rcv = recvfrom(__udp_sock, buffer, PACKET_SIZE, 0, (struct sockaddr *) &server_addr, (socklen_t * __restrict__)&len);
				if (rcv > 512) 
					goto _get_out_of_here_its_gonna_blow;
				if (rcv != -1) {
					_retme = n_malloc(PACKET_SIZE);
					for (i = 0;i < PACKET_SIZE; i++) 
						_retme[i] = buffer[i];
					sendto(new_fd, _retme, rcv, 0,(struct sockaddr *)&client_addr, len);
					close(new_fd);
				}
				goto _get_out_of_here_its_gonna_blow;
			}
		}
	}
	_get_out_of_here_its_gonna_blow:
	if ((__dns != NULL) && (sizeof(__dns) >= divide_by))
		free(__dns);
	if ((_dns_ip != NULL) && (sizeof(_dns_ip) >= divide_by))
		free(_dns_ip);
	close(__udp_sock);
	pthread_mutex_unlock(&mutex);
}

static inline char *craft_dns_ns_response(char *qid, char *dns_response, int receive) 
{
	char *a_name, *my_dns_response = NULL;
	int i;

	a_name = parse_enumerate_and_fetch_each_octet_and_just_return_a_name(dns_response, receive);
	for (i = 0; i < zone_count; i++) {
		if ((strcmp((_ret_st_mainstruct_domain_zone + i)->domain_zone, a_name)) == 0) 
			my_dns_response = do_craft_dns_ns_response(qid, dns_response, receive, i, a_name);
	}
	if (my_dns_response == NULL)
               return (char *)'\0';

	return  my_dns_response;	
}

static inline char *do_craft_dns_ns_response(char *qid, char *dns_response, int receive, int zone_uid, char *a_name)
{
	int i, j , len_the_ns  = 0, num_of_answer  = 0, len_a_name = 0, residue  = 0, mode, len_new_mode = 0;
	char *tmp_ns_host, *current_domain_pointer;
	char *the_ns = NULL;
	char *crafted_dns_response, *my_tmp_ns = NULL;
	
	/*
	on development process
	for (i = 0; i < 512; i++) 
		printf("hex packet : [%d] : [0x%x] = [%c] \n", i, (unsigned)(unsigned char)dns_response[i], dns_response[i]);
	*/
	if (a_name != NULL)
		len_a_name = strlen(a_name);
	crafted_dns_response = dns_response;
	num_of_answer = (_ret_st_mainstruct_domain_zone + zone_uid)->domain_zone_ns_count;
	num_of_answer++;
	current_domain_pointer = (_ret_st_mainstruct_domain_zone + zone_uid)->domain_zone;
	crafted_dns_response[0] = (char)qid[0];
	crafted_dns_response[1] = (char)qid[1];
	crafted_dns_response[2] = (char)0x85;
	crafted_dns_response[3] = (char)0x00;
	crafted_dns_response[4] = (char)0x0;
	crafted_dns_response[5] = (char)0x01; /* question number */ 
	crafted_dns_response[6] = (char)0x00; 
	crafted_dns_response[7] = (char)num_of_answer;
	crafted_dns_response[8] = (char)0x0;
	crafted_dns_response[9] = (char)0x0; /* authority rrs */ 
	crafted_dns_response[10] = (char)0x0;
	crafted_dns_response[11] = (char)0x0; /* additional records */
	for (i = 1; i <= num_of_answer; i++) {
		mode = 0;
		crafted_dns_response[receive++] = (char)0xc0;
		crafted_dns_response[receive++] = (char)0xc; /* offset */ 
		crafted_dns_response[receive++] = (char)0x00;
		crafted_dns_response[receive++] = (char)0x02; /* answer type : ns */ 
		crafted_dns_response[receive++] = (char)0x00;
		crafted_dns_response[receive++] = (char)0x01; /* class */ 
		crafted_dns_response[receive++] = (char)0x00;
		crafted_dns_response[receive++] = (char)0x01;
		crafted_dns_response[receive++] = (char)0x51;
		crafted_dns_response[receive++] = (char)0x80; /* ttl */ 
		crafted_dns_response[receive++] = (char)0x00;
		if ((sizeof(((_ret_struct_ns) + zone_uid)->ns[i]) > 0) && (((_ret_struct_ns) + zone_uid)->ns[i] != NULL))	
			tmp_ns_host = ((_ret_struct_ns) + zone_uid)->ns[i];
		if ((strstr(current_domain_pointer, tmp_ns_host) != NULL) || strstr(tmp_ns_host, ".") == NULL)
			the_ns = _do_fetch_self_ns(tmp_ns_host);
		else {
			the_ns = tmp_ns_host;
			mode = 1;
		}
		if (the_ns == NULL) 
			goto out_ns;
		len_the_ns = (int)strlen(the_ns);
		if (mode == 0) {
			if ((dns_response != NULL) && (a_name != NULL)) {
				if ((dns_response[13] != a_name[0]) && (dns_response[14] != a_name[1])) {
					mode = 2;
					my_tmp_ns = n_malloc(len_the_ns + len_a_name + 1);
					snprintf(my_tmp_ns, sizeof(my_tmp_ns) + 1, "%s.%s",the_ns, a_name);
					if (my_tmp_ns != NULL)
						len_new_mode = (int)strlen(my_tmp_ns);
				}
			}
			if ((len_the_ns == 3) && (mode != 2)) {
				crafted_dns_response[receive++] = (char)0x06;
				crafted_dns_response[receive++] = (char)len_the_ns;  
			}
			else if ((len_the_ns >= MAX_NS_LENGTH) && (mode != 2)) {
				crafted_dns_response[receive++] = (char)0x06;
				crafted_dns_response[receive++] = (char)0x03;   
			}
			else if (mode == 0) {
				residue = len_the_ns - 3;
				crafted_dns_response[receive++] = (char)(0x06 + residue);
				crafted_dns_response[receive++] = (char)len_the_ns;  
			}
			else if ((len_new_mode >= MAX_NS_LENGTH) && (mode == 2)) {
				crafted_dns_response[receive++] = (char)0x06;
				crafted_dns_response[receive++] = (char)0x03;   
			}
			else if (mode == 2) {
				residue = len_new_mode - 4;
				crafted_dns_response[receive++] = (char)(0x06 + residue);
				crafted_dns_response[receive++] = (char)len_new_mode;  
			}
			/* addition processing */	
			if (mode != 2) {
				for (j = 0; j < len_the_ns; j++) 
					crafted_dns_response[receive++] = (char)the_ns[j];
				crafted_dns_response[receive++] = (char)0xc0;
				crafted_dns_response[receive++] = (char)0xc; 
			}
			else {
				for (j = 0; j < len_new_mode; j++) 
					crafted_dns_response[receive++] = (char)my_tmp_ns[j];
				crafted_dns_response[receive++] = (char)0x00;
			}
		}
		else if (mode == 1) {
			if (len_the_ns == 3) {
				crafted_dns_response[receive++] = (char)0x06;
				crafted_dns_response[receive++] = (char)len_the_ns;  
			}
			else if (len_the_ns >= MAX_NS_LENGTH) {
				crafted_dns_response[receive++] = (char)0x06;
				crafted_dns_response[receive++] = (char)0x03;   
			}
			else	{
				residue = len_the_ns - 4;
				crafted_dns_response[receive++] = (char)(0x06 + residue);
				crafted_dns_response[receive++] = (char)len_the_ns;  
			}
			for (j = 0; j < len_the_ns; j++) 
				crafted_dns_response[receive++] = (char)the_ns[j];
			crafted_dns_response[receive++] = (char)0x00;
		}
	}
	out_ns:
	(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive = receive; 
	
	return crafted_dns_response;
}

static inline char *craft_dns_mx_response(char *qid, char *dns_response, int receive)
{
	char *a_name = NULL, *my_dns_response = NULL;
	int i;

	a_name = parse_enumerate_and_fetch_each_octet_and_just_return_a_name(dns_response, receive);
	if (a_name != NULL) {
		for (i = 0; i < zone_count; i++) {
			if ((strcmp((_ret_st_mainstruct_domain_zone + i)->domain_zone, a_name)) == 0) {
				my_dns_response = do_craft_dns_mx_response(qid, dns_response, receive, i, a_name);
			}
		}
	}
	if (my_dns_response == NULL)
               return (char *)'\0';
			
	return my_dns_response;
}

static inline char *do_craft_dns_mx_response(char *qid, char *dns_response, int receive, int zone_uid, char *a_name)
{
	char *tmp_mx_host, *current_domain_pointer;
	char *host_piece = NULL;
	int new_len  = 0, len_host_mx = 0, self_mx_mode = 1, i , len_new_mode = 0, len_a_name = 0, count_len = 0 ;
	char *crafted_dns_response = NULL, *my_tmp_mx_host = NULL;

	if (a_name != NULL)
		len_a_name = (int)strlen(a_name);
	crafted_dns_response = dns_response;
	current_domain_pointer = (_ret_st_mainstruct_domain_zone + zone_uid)->domain_zone;
	/* setup flags */
	crafted_dns_response[0] = (char)qid[0];	
	crafted_dns_response[1] = (char)qid[1];	
	crafted_dns_response[2] = (char)0x85;
	crafted_dns_response[3] = (char)0x00;
	crafted_dns_response[4] = (char)0x0;
	crafted_dns_response[5] = (char)0x1; /* defined question num */
	crafted_dns_response[6]= (char)0x0;
	crafted_dns_response[7] = (char)0x2; /* answer num */
	crafted_dns_response[8] = (char)0x0;
	crafted_dns_response[9] = (char)0x00; /* NSCount : Authority Record Count */
	crafted_dns_response[10] = (char)0x0;
	crafted_dns_response[11] = (char)0x0; /* ARCount : Additional Record Count: Specifies the number of resource records in the Additional section of the message.*/
	/* craft answer section */
	crafted_dns_response[receive++] = (char)0xc0;
	crafted_dns_response[receive++] = (char)0x0c; /* defined offset  */
	crafted_dns_response[receive++] = (char)0x0;
	crafted_dns_response[receive++] = (char)0x0f; /* mx answer type */
	crafted_dns_response[receive++] = (char)0x0;
	crafted_dns_response[receive++] = (char)0x01; /* class */
	crafted_dns_response[receive++] = (char)0x0;
	crafted_dns_response[receive++] = (char)0x0;
	crafted_dns_response[receive++] = (char)0x01;
	crafted_dns_response[receive++] = (char)0x2c;  /* ttl */
	if ((sizeof(((_ret_struct_mx) + zone_uid)->mx_host) >= divide_by)   && ((((_ret_struct_mx) + zone_uid)->mx_host) != NULL )) {
		tmp_mx_host = n_malloc((int)strlen(((_ret_struct_mx) + zone_uid)->mx_host));
		count_len = (int)strlen(((_ret_struct_mx) + zone_uid)->mx_host);
		#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
		strlcpy(tmp_mx_host, ((_ret_struct_mx) + zone_uid)->mx_host, (size_t)count_len + 1);
		#else
		strncpy(tmp_mx_host, ((_ret_struct_mx) + zone_uid)->mx_host, (size_t)count_len);
		#endif	
		if (strstr(tmp_mx_host, ".") != NULL) {
			if (strstr(tmp_mx_host, current_domain_pointer) != NULL) {
				if ((host_piece = strtok(tmp_mx_host, ".")) == NULL) 
					goto out_this_scope;
			}
			else {
				host_piece = tmp_mx_host;
				self_mx_mode = 0;
			}
		}
		else
			host_piece = tmp_mx_host;
		if ((sizeof(host_piece) > 0) && (host_piece != NULL)) {
			len_host_mx = (int)strlen(host_piece);
			if ((dns_response[13] != a_name[0]) && (dns_response[14] != a_name[1])) {
				self_mx_mode = 2;
				my_tmp_mx_host = n_malloc(len_host_mx + len_a_name + 1);
				snprintf(my_tmp_mx_host,sizeof(my_tmp_mx_host) + 1 ,"%s.%s", host_piece, a_name);
				if (my_tmp_mx_host != NULL)
					len_new_mode = (int)strlen(my_tmp_mx_host);
			}
			if ((len_host_mx > 0) || (self_mx_mode == 2)) {
				if ((len_host_mx > 4) || (len_new_mode > 4))  {
					if (self_mx_mode == 1)
						new_len = (len_host_mx - 4) + 9;
					else if (self_mx_mode == 2)
						new_len = (len_new_mode - 4) + 9;
					else
						new_len = (len_host_mx - 5) + 9;
				}					
				else
					new_len = 0x9;	
				crafted_dns_response[receive++] = (char)0x0;
				if (self_mx_mode == 2) 
					crafted_dns_response[receive++] = (char)len_new_mode; /* length */
				else
					crafted_dns_response[receive++] = (char)new_len; /* length */
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0xA;  /* preference = 10 */
				if (self_mx_mode == 2) {
					crafted_dns_response[receive++] = (char)len_new_mode;
					for (i = 0;i < len_new_mode; i++) 
						crafted_dns_response[receive++] = (char)my_tmp_mx_host[i];
				}
				else {
					crafted_dns_response[receive++] = (char)len_host_mx;
					for (i = 0;i < len_host_mx; i++) 
						crafted_dns_response[receive++] = (char)host_piece[i];
				}
			}
		}
	}
	if (self_mx_mode == 1) {	
		crafted_dns_response[receive++] = (char)0xc0;
		crafted_dns_response[receive++] = (char)0xc;
	}
	else
		crafted_dns_response[receive++] = (char)0x0;
	(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive = receive;
	out_this_scope:
	if ((host_piece != NULL) && (sizeof(host_piece) >= divide_by))
		free(host_piece);
	if (crafted_dns_response == NULL)
		return (char *)'\0';
	
	return  crafted_dns_response;	
}

static void _rldns_check_cred()
{
	int uid  = 0, euid  = 0;
		
	uid = getuid();
	if (uid != 0) {
		euid = geteuid();
		if (euid != 0) {
			fprintf(stdout, "\tSorry rldns must be run as root ! rldns exit !\n");
			exit(0);
		}
	}
}

static int _check_self_and_check_proc(char *self)
{
	FILE *fp = NULL;
	int retme, len = 0, count = 0;
	char str[256] = "\0";
	
	fp = popen("ps aux | grep rldns", "r");
	if (fp != NULL) {	
		while ((fgets(str, max_buf, fp)) != NULL) {
			len = (int)strlen(str);
			if ((len > 1)) {
				if ((strstr(str, "rldns") != NULL) && (strstr(str, "grep") == NULL) && (strstr(str, "gedit") == NULL) && (strstr(str, "nano") == NULL) && (strstr(str, "objdump") == NULL) && (strstr(str, "hexedit") == NULL) && (strstr(str, "SciTE") == NULL))
					count++;
			}
		}
	}
	if (fp != NULL)
		pclose(fp);
	if (count > 2) {
		retme = -2;
		goto outme;	
	}
	if ((strcmp(self, "rldns") == 0) || (strcmp(self, "./rldns") == 0))
		retme = 1;
	else 
		retme = -1;
	outme:

	return retme;	
}

/** string trimming functions modified from http://en.wikipedia.org/wiki/Trimming_%28computer_programming%29#C.2FC.2B.2B **/
static inline char *rtrim(char *str)
{
	int n = 0;
	char *ret_str = "X";
	
	if (str != NULL) {
		n = (int)strlen(str);
		while (n > 0 && isspace((unsigned char)str[n - 1])) 
			n--;
		str[n] = '\0';
		if (str != NULL) {
			ret_str = n_malloc((int)strlen(str));
			if (ret_str == NULL) {
				ret_str = "X";
			}
			#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
			strlcpy(ret_str, str, strlen(str) + 1);
			#else
			strncpy(ret_str, str, strlen(str));
			#endif
		}
	}
	if (ret_str == NULL) 
		return "X";
	
	return ret_str;
}
 
static inline char *ltrim(char *str)
{
	char *ret_str = NULL;
	int n = 0;
	
	if (str == NULL) {
		ret_str = "X";
		goto out_ltrim;
	}
	ret_str = n_malloc((int)strlen(str));
	#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
	strlcpy(ret_str, str, strlen(str));
	#else
	strncpy(ret_str, str, strlen(str));
	#endif
	while (str[n] != '\0' && isspace((unsigned char)str[n])) 
		n++;
	memmove(ret_str, str + n, strlen(str) - n + 1);
	if (ret_str == NULL)
		return (char *)'\0';
	out_ltrim:
	
	return ret_str;
}
 
static inline char *trim(char *str)
{
	char *ret_str = NULL, *bef_ret = NULL, *final_ret = NULL;
	
	if (str != NULL) {
		if ((str[0] != '\0') && (str[0] != '\x00')) {
			if (sizeof(str) > 0) {
				ret_str = rtrim(str);
				bef_ret = ltrim(ret_str);
			}
		}
		if (bef_ret != NULL) 
			final_ret = bef_ret;
		else {
			final_ret = n_malloc((int)strlen(str));
			#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
			strlcpy(final_ret, str, strlen(str));
			#else
			strncpy(final_ret, str, strlen(str));
			#endif
		}
	}
	else 
		return (char *)'\0';
	if (final_ret == NULL)
		return (char *)'\0';
		
	return final_ret;
}

int main(int argc, char *argv[])
{	
	int daemonize_res , retself = 0;
	char *current_self;
	
	current_self = argv[0];
	retself = _check_self_and_check_proc(current_self);
	if (retself == -2)
            _msg_terminated_err(rldns_already_run);
	__check_machine_support();
	_check_config();
	_cfg = _init_read_parse_config();
	rldns_port = _cfg[0].port;
	daemonize_res = daemonize();
        if (daemonize_res == 0)
            rldns_main();
        
	return 0;
}

static void rldns_main()
{
	int  i = 0, receive = 0, a_length = 0, valid_dns;
	char *dns_packet, *client_ip, *a_name = NULL, *dns_response_type, *qid, *answer_type, *final_dns_packet;
	int rcv_flag = 0;
	int recursive_req = 0;
	pid_t pid;
	fd_set selectfds;
	struct timeval timeout;
	pthread_t tid;
	int count_len = 0;
	
	_rldns_check_cred();
        _prepare_logs();
        _read_zone_file();
        _ret_st_struct_current_dns_resp = malloc(100 *sizeof(_st_struct_current_dns_resp));
	dns_packet = n_malloc(PACKET_SIZE);
	rldns_sock = _create_udp_sock();
	rldns_sock = nb_bind(rldns_sock);
	_init_set_cred();
	len = (int)sizeof(client_addr);
	_sig_handler(0);
	signal (SIGCHLD, _sig_handler);
	for (i = 1; i < worker; i++)  {
		pid = fork();
		if (pid == 0) 
			goto start;
	}
	start:
	timeout.tv_sec = 8;
	timeout.tv_usec = 10000;
	setsockopt(rldns_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	while(1) {
		repeat:
		usleep(1000);
		timeout.tv_sec = 10;
		timeout.tv_usec = 10000;
		FD_ZERO(&selectfds);
		FD_SET(rldns_sock, &selectfds);
		if (select(sizeof(selectfds) * divide_by, &selectfds, NULL, NULL, &timeout) == 0) {
			continue;
		}
		else {
			receive = recvfrom(rldns_sock, dns_packet, PACKET_SIZE, rcv_flag, (struct sockaddr *) &client_addr, (socklen_t * __restrict__)&len);
			if (receive < 0) 
				continue;
			else {
				generic_answer_type = NULL;
				valid_dns = 1;
				/* blocking some malformed dns request */
				valid_dns = analyze_invalid_dns_request(dns_packet, receive);
				if (valid_dns == 0) 
					goto repeat;
				client_ip = inet_ntoa(client_addr.sin_addr);
				(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive = receive;
				rldns_log(LOG_IP, client_ip);
				a_name = parse_enumerate_and_fetch_each_octet_and_just_return_a_name(dns_packet, receive);
				a_length = strlen(a_name);
				if ((strlen(dns_packet) <= PACKET_SIZE) && (a_length < MAX_A_LENGTH_ALLOWED) && (a_length > 3)) {
					recursive_req = 0;
					qid = get_current_dns_qid(dns_packet);
					recursive_req = _find_a_name_at_zones_ret_recursive_or_not(a_name);
					if (recursive_req == 1) 
						goto out;
					dns_response_type = determine_dns_request_type(dns_packet);
					if (strcmp(dns_response_type, "A") == 0)  {
						if (generic_answer_type != NULL) {
							answer_type = n_malloc((int)strlen(generic_answer_type));
							count_len = (int)strlen(generic_answer_type);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(answer_type, generic_answer_type, (size_t)count_len);
							#else
							strncpy(answer_type, generic_answer_type, (size_t)count_len);
							#endif
						}
						else {
							answer_type = n_malloc(strlen(A_DEFAULT));
							count_len = (int)strlen(A_DEFAULT);
							#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
							strlcpy(answer_type, A_DEFAULT, (size_t)count_len);
							#else
							strncpy(answer_type, A_DEFAULT, (size_t)count_len);
							#endif
						}
						if (strcmp(answer_type, RET_NS_IP) == 0) {
							final_dns_packet = craft_dns_aname_response(qid, dns_packet, receive, MOD_NS, (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_ns_resolved_ip);
							receive = (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive;
						}
						else if (strcmp(answer_type, RET_NO_ANSWER) != 0) {
							final_dns_packet = craft_dns_aname_response(qid, dns_packet, receive, MOD_BASIC, a_name);
							receive = (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive;
						}
					}				
					else if (strcmp(dns_response_type, "mx") == 0) {
						final_dns_packet = craft_dns_mx_response(qid, dns_packet, receive);
						receive = (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive;
					}
					else if (strcmp(dns_response_type, "ns") == 0)  {
						final_dns_packet = craft_dns_ns_response(qid, dns_packet, receive);
						receive = (_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive;
					}
					/*
					for (i = 0; i <= receive; i++) {
					    printf("[%x]", final_dns_packet[i]);
					}
					*/
					out:
					if ((recursive_req == 1) && (a_name != NULL) && (dns_packet != NULL)) {
						generic_a_name = n_malloc((int) strlen(a_name));
						if (a_name == NULL)
							goto repeat;
						memcpy(generic_a_name, a_name, strlen(a_name));
						generic_packet = n_malloc(PACKET_SIZE);
						for (i = 0; i < PACKET_SIZE; i++)
							generic_packet[i] =  dns_packet[i];
						pthread_create(&tid, NULL, &__craft_dns_recursive_query, NULL);
						recursive_req = 0;
					}
					else 
						sendto(rldns_sock, final_dns_packet, receive, rcv_flag,(struct sockaddr *)&client_addr, len);
				}	
				else
					goto repeat;
			}
		}
	}
	fflush(stdout);
	close(rldns_sock);
}

static inline char *_set_randomize_a_ip(int zone_uid)
{
	boolean valid = _false;
	char *aray_rand;
	char *total_ip_sequence = NULL, *add_this = NULL;
	int found = 0, _rand = 0, i, try = 0, range, amount = 0, how_many = 0, j;
	
	how_many = (int)(_ret_st_mainstruct_domain_zone + zone_uid)->domain_zone_a_ip_count;
	if (how_many > 18) 
		how_many = 18;	
	range = (int)_ret_st_mainstruct_domain_zone[zone_uid].domain_zone_a_ip_count + 1;
	if (range > 18)
		range = 18;
	aray_rand = n_malloc(range);
	for (j = 0; j <= range; j++)
			aray_rand[j] = (char)0x0;
	total_ip_sequence = n_malloc(16 * _ret_st_mainstruct_domain_zone[zone_uid].domain_zone_a_ip_count + _ret_st_mainstruct_domain_zone[zone_uid].domain_zone_a_ip_count);
	for (i = 0; i <= how_many; i++) {
		try++;
		if ((try > 1000)) 
			break;
		found = 1;
		#if defined(__FreeBSD__)  || defined(__OpenBSD__)  || defined(__NetBSD__) 
			/* rand() and random() on openbsd before patch has a bug so I use arc4random family as alternative :p */
			_rand = arc4random_uniform(range + 1);
		#else
		    #if defined(__ARM_ARCH_7__) ||  defined(__ARM_ARCH_7A__) ||  defined(__ARM_ARCH_7R__) ||  defined(__ARM_ARCH_7S__) ||  defined(__ARM_ARCH_7M__)
			srand((unsigned int) seed_rng());
			_rand = rand() %(range + 1);
                    #else
			_do_prctl();
			srandom((unsigned int)rdtsc());
			_rand = random() % (range + 1);
                 #endif
		#endif
		if (_rand == 0)
			_rand = 1;
		if (sizeof(aray_rand) < divide_by) 
			goto out;
		found = 1;
		found = find_element(aray_rand, _rand);	
		if (found == 0) {
			amount++;
			aray_rand[i] = (char)_rand;
			add_this = _switch_rand(_rand, zone_uid);
			if (add_this != NULL) {
				valid = validate_ipv4_octet(add_this);
				if (valid == _true) {
					strcat(total_ip_sequence, add_this);
					strcat(total_ip_sequence, "|");
				}
			}
			if (amount > how_many) 				
				goto out;
		}
		else
			i--;
	}	
	out:
	total_ip_sequence = _last_replace(total_ip_sequence, "|", "");
	if (total_ip_sequence == NULL) 
		return (char *)'\0';
	
	return total_ip_sequence;
}	

/** rldns processing a name and cname **/
static inline char *craft_dns_aname_response(char *qid, char *dns_response, int receive, char *mode, char *ns_ip_or_a_name)
{
	int i, a_counter = 0;
	char *total_res_ip = NULL, *crafted_dns_response = NULL;
	char *my_ns_ip = NULL;
	char *my_a_name = NULL;
	
	if (ns_ip_or_a_name == NULL)
		goto out;
	if ((mode != NULL) && sizeof(mode) >= divide_by) {
		if (strcmp(mode, MOD_NS) == 0) {
			my_ns_ip = ns_ip_or_a_name;
			crafted_dns_response = do_craft_dns_aname_ns_ip_resolve(qid, dns_response, receive, my_ns_ip);
		}
		else {
			my_a_name = ns_ip_or_a_name;
			for (i = 0; i < zone_count; i++) {
				if ((strcmp((_ret_st_mainstruct_domain_zone + i )->domain_zone, my_a_name)) == 0) {
					if (strcmp(mode, MOD_NS) != 0) {
						a_counter = (int)(_ret_st_mainstruct_domain_zone[i].domain_zone_a_ip_count);
						if (resolver_type == 1) 
							total_res_ip = _set_non_randomize_a_ip((_ret_st_mainstruct_domain_zone + i)->uid);
						else if (resolver_type == 2) {
							if (a_counter < 2) 
								total_res_ip = _set_non_randomize_a_ip((_ret_st_mainstruct_domain_zone + i)->uid);
							else	
								total_res_ip = _set_randomize_a_ip((_ret_st_mainstruct_domain_zone + i)->uid);
						}
						if ((total_res_ip != NULL) && sizeof(total_res_ip) > 0) 
							crafted_dns_response = do_craft_dns_aname_response(total_res_ip, qid, dns_response, receive, (_ret_st_mainstruct_domain_zone + i)->uid);
					}
					else 
						crafted_dns_response = do_craft_dns_aname_ns_ip_resolve(qid, dns_response, receive, my_ns_ip);
					break;
				}
			}
		}
	}
	out:
	if (crafted_dns_response == NULL)
		return (char *)'\0';
	
	return crafted_dns_response;
}

static inline char *do_craft_dns_aname_ns_ip_resolve(char *qid, char *dns_response, int receive, char *ns_ip)
{
	char *octet, *crafted_dns_response = NULL;
	
	if ((dns_response != NULL) && (sizeof(dns_response) >= divide_by)) {
		crafted_dns_response = dns_response;
		/** craft dns header **/
		crafted_dns_response[0] = (char)qid[0];	
		crafted_dns_response[1] = (char)qid[1];			
		crafted_dns_response[2] = (char)0x81;
		crafted_dns_response[3] = (char)0x80;
		crafted_dns_response[4] = (char)0x0;
		crafted_dns_response[5] = (char)0x1;
		crafted_dns_response[6] = (char)0x0;
		crafted_dns_response[7] = (char)0x1;
		crafted_dns_response[8] = (char)0x0;
		crafted_dns_response[9] = (char)0x0; /** NSCount : Authority Record Count **/
		crafted_dns_response[10] = (char)0x0;
		crafted_dns_response[11] = (char)0x0; /**ARCount : Additional Record Count: Specifies the number of resource records in the Additional section of the message.**/
		/** craft dns response **/
		crafted_dns_response[receive++] = (char)0xc0;
		crafted_dns_response[receive++] = (char)0xc;   /** offset **/
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x1;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x1;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x3c;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x4;
		octet = strtok(ns_ip, ".");
		while (octet != NULL) {
			crafted_dns_response[receive++] = (char)atoi(octet);
			octet = strtok(NULL, ".");
		}
		(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive = receive;
	}
	if (dns_response == NULL)
		return (char *)'\0';
	if (crafted_dns_response == NULL)
		return (char *)'\0';
	
	return crafted_dns_response;	
}

static inline char *do_craft_dns_aname_response(char *total_res_ip, char *qid, char *dns_response, int receive, int zone_uid)
{
	char *crafted_dns_response = NULL;
	char *tot_res = NULL, *tmp_data;
	int i , j, number_of_answer = 2, octet_num;
	char *piece = NULL;
	char *octet = NULL;
	typedef struct {
		char *ip;	
	}_tmp_data;
	_tmp_data *__tmp_data = NULL;
	
	if ((total_res_ip != NULL) && (dns_response != NULL)) {
		crafted_dns_response = dns_response;
		__tmp_data = malloc(18 * sizeof(__tmp_data));
		tot_res = n_malloc((int)strlen(total_res_ip));
		for (i = 0; i < (int)strlen(total_res_ip); i++)
			tot_res[i] = total_res_ip[i];
		number_of_answer = _count_answer_length(tot_res, "answer_count");
		number_of_answer++;
		/** craft dns header **/
		crafted_dns_response[0] = (char)qid[0];	
		crafted_dns_response[1] = (char)qid[1];			
		crafted_dns_response[2] = (char)0x81;
		crafted_dns_response[3] = (char)0x80;
		crafted_dns_response[4] = (char)0x0;
		crafted_dns_response[5] = (char)0x1;
		crafted_dns_response[6] = (char)0x0;
		crafted_dns_response[7] = (char)number_of_answer;
		crafted_dns_response[8] = (char)0x0;
		crafted_dns_response[9] = (char)0x0; /** NSCount : Authority Record Count **/
		crafted_dns_response[10] = (char)0x0;
		crafted_dns_response[11] = (char)0x0; /**ARCount : Additional Record Count: Specifies the number of resource records in the Additional section of the message.**/
		i = 0;
		if (strstr(total_res_ip, "|") != NULL) {
			piece = strtok(total_res_ip, "|");
			while (piece != NULL) {
				(__tmp_data + i)->ip = piece;	
				piece = strtok(NULL, "|");
				i++;
			}
			for (j = 0;j < i; j++) {
			  	tmp_data = n_malloc((int)strlen((__tmp_data + j)->ip));
				#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
				strlcpy(tmp_data, (__tmp_data + j)->ip, strlen((__tmp_data + j)->ip) + 1);
				#else
				strcpy(tmp_data, (__tmp_data + j)->ip);
				#endif		
				/** craft answer section **/
				crafted_dns_response[receive++] = (char)0xc0;
				crafted_dns_response[receive++] = (char)0xc;   /** offset **/
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x1;
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x1;
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x3c;
				crafted_dns_response[receive++] = (char)0x0;
				crafted_dns_response[receive++] = (char)0x4;
				octet = strtok(tmp_data, ".");
				octet_num = 0;
				while ((octet != NULL) && (octet_num <= 4) /* ip v4 address format only */) {
					crafted_dns_response[receive++] = (char)atoi(octet);
					octet = strtok(NULL, ".");
					octet_num++;
				}
			}
		}
		else {
			/** processing single ip address **/
			crafted_dns_response[receive++] = (char)0xc0;
			crafted_dns_response[receive++] = (char)0xc;   /** offset **/
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x1;
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x1;
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x3c;
			crafted_dns_response[receive++] = (char)0x0;
			crafted_dns_response[receive++] = (char)0x4;
			tmp_data = n_malloc(16);
			#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
			strlcpy(tmp_data, (_ret_struct_a_res + zone_uid)->a_ip[1], 16);
			#else
			strncpy(tmp_data, (_ret_struct_a_res + zone_uid)->a_ip[1], 16);
			#endif	
			octet = strtok(tmp_data, ".");
			octet_num = 0;
			while ((octet != NULL) && (octet_num <= 4) /* ip v4 address format only */) {
				crafted_dns_response[receive++] = (char)atoi(octet);
				octet = strtok(NULL, ".");	
				octet_num++;
			}
		}
		crafted_dns_response[receive++] = (char)0xc0;
		crafted_dns_response[receive++] = (char)0xc;   /** offset **/
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x1;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x1;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x0;
		crafted_dns_response[receive++] = (char)0x3c;
		crafted_dns_response[receive++] = (char)0x0;
 		crafted_dns_response[receive++] = (char)0x4;
			
		(_ret_st_struct_current_dns_resp + rldns_response_id)->_cur_receive = receive;
	}
	if ((tot_res != NULL) && sizeof(tot_res) >= divide_by)
		free(tot_res);
	if ((__tmp_data != NULL) && sizeof(__tmp_data) >= divide_by)
		free(__tmp_data);
	if (crafted_dns_response == NULL) 
		return (char *)'\0';
	  
	return  crafted_dns_response;	
}

static inline void rldns_log(char *log_type, char *msg)
{
	int pjg_file = 0, retfunc = 0;
	FILE *log;
	char *fulltime = "";
	time_t curtime;
        struct tm *loctime;
	char *whatlog = NULL;
	int day = 0, month = 0, year = 0;
	
	curtime = time (NULL);
        loctime = localtime (&curtime);
	fulltime = asctime (loctime);
	fulltime = trim(fulltime);
	day = loctime->tm_mday;
	month = loctime->tm_mon + 1;
	year = loctime->tm_year + 1900;
	/*
	if (strcmp(log_type, LOG_BAN) == 0) {
		whatlog = n_malloc((int)strlen(ban_ip_log_file));
		if (whatlog != NULL)
			strncpy(whatlog, ban_ip_log_file, strlen(ban_ip_log_file));
	}
	*/
	if (strcmp(log_type, LOG_IP) == 0) {
		whatlog = n_malloc((int)strlen(log_ip_file));
		if (whatlog != NULL)
			strncpy(whatlog, log_ip_file, strlen(log_ip_file));
	}
	if (whatlog != NULL) {
		pjg_file = (int)get_file_length_or_line_count(whatlog, "length");
		if (pjg_file > 100000) 
			log = fopen(whatlog, "w");
		else 
			log = fopen(whatlog, "a");
		if (log != NULL) {
			if (strcmp(log_type, "ip_log") == 0) 
				fprintf (log, "%d/%d/%d|%s\n", day, month, year, msg);
			else {
				if ((fulltime !=NULL) && (msg != NULL))
					fprintf (log, "%s - %s\n", fulltime, msg);
			}
			if (log != NULL) {
				retfunc = fclose(log);
				if (retfunc != 0)
					_msg_err(fail_to_closefd);
			}
		}
	}
	if ((fulltime != NULL) && (sizeof(fulltime) >= divide_by))
		free(fulltime);
	if ((whatlog != NULL) && (sizeof(whatlog) >= divide_by))
		free(whatlog);
}

static void _prepare_logs()
{
	int uid = 1, res = 0;
	struct stat filestat;
	char *prepare_log_path_cmd;
	int total_log_len = ((int)strlen(log_ip_file)) * 3;
	int retfunc = 0;

	prepare_log_path_cmd = n_malloc(total_log_len + 31);
	retfunc = snprintf(prepare_log_path_cmd, (size_t)(total_log_len + 31) , "touch %s;chmod 644 %s;chown rldns %s", log_ip_file, log_ip_file, log_ip_file);
	if (retfunc == 0)
		_msg_terminated_err(fail_to_set_logs);	
	uid = getuid();
	if (uid == 0) {
		res = stat(log_ip_file, &filestat);
		if (res < 0)		
			system(prepare_log_path_cmd);
		res = stat(log_ip_file, &filestat);
		if (res < 0)		
			_msg_terminated_err(fail_to_set_logs);
	}
}

