/*
 * rldns 1.4
 *  (c) Copyright by Indodev All Rights Reserved 
 * indodev.asia
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
 
 
#ifndef _structs_h_
#define _structs_h_

struct sockaddr_in server_addr;   
struct sockaddr_in client_addr;

typedef struct {
	unsigned int _cur_receive;
	char *_cur_ns_resolved_ip;
	char *_cur_a_name;
} _st_struct_current_dns_resp;

typedef struct {
	unsigned int resolver_type;
	unsigned int port;
	unsigned int worker;
	char *version;
	char *zones;
	char *dns1;
	char *dns2;
}_st_configurations;

typedef struct {
	unsigned int uid;
	char *a_ip[19];
}_st_a_res;

typedef struct {
	unsigned int uid;
	char *cname[6];
} _st_cname;

typedef struct {
	unsigned int uid;
	char *mx_host;
} _st_mx;

typedef struct {
	unsigned int uid;
	char *ns[5];
	char *ns_ip[5];
} _st_ns;

typedef struct {
	unsigned int uid;
	char *zone_aname;
} _st_zone;

typedef struct {
	unsigned int uid;	
	char *domain_zone;
	unsigned int domain_zone_a_ip_count;
	unsigned int domain_zone_cname_count;
	unsigned int domain_zone_mx_count;
	unsigned int domain_zone_ns_count;
} _st_mainstruct_domain_zone;

_st_configurations *_cfg;
_st_mainstruct_domain_zone *_ret_st_mainstruct_domain_zone;	
_st_zone *_ret_struct_dns_zone;
_st_a_res *_ret_struct_a_res;
_st_cname *_ret_struct_cname;
_st_mx *_ret_struct_mx;
_st_ns *_ret_struct_ns;
_st_struct_current_dns_resp *_ret_st_struct_current_dns_resp;

#endif
