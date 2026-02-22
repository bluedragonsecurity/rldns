/*
 * rldns 1.4
 *  (c) Copyright by Indodev All Rights Reserved 
 * indodev.asia
 * Developed by Antonius (w1sd0m) - bluedragonsec.com
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
 
 
rfc  reference
- http://tools.ietf.org/html/rfc1035

for a resolver 
this dns software has 2 types method to resolve a name request
- Resolver Type 1, if more than 1 ip to resolve, this will do a dns based load balancing without randomizing ip addresses (for a name request only)
- Resolver Type 2, if more than 1 ip to resolve, this will randomize multiple ip sequences for dns based load balancing (for a name request only)
By default, resolver type is 2 (suggested for best a name resolve performance)
*/

#ifndef _vars_h_
#define _vars_h_

unsigned int airhax_mode  = 1;
static const char *log_ip_file = "/var/log/rldns_iplog"; 
unsigned int resolver_type = 2;
static const char *user = "rldns";
unsigned int _counter = 0;
unsigned int tsc = 1;
unsigned int rldns_port = 53;
unsigned int recursive_dns_port = 53;
unsigned int worker = 2;
unsigned int rldns_sock;
unsigned int len = 0;
unsigned int tmp_domain_uid;
char *version = "rldns-1.4";
char *zones_path = "zones/";
/* recursive default setting */
char *recursive_dns1 = "8.8.8.8";
char *recursive_dns2 = "8.8.4.4";
char *generic_packet;
char *generic_a_name;
char *generic_answer_type;
char *generic_full_a_name_requested;
static const char *special_tld[] = {".or.", ".co.", ".web.", ".ac.", ".sch.", ".go.", ".biz.", ".desa.", ".mil.", ".net.", ".int.", ".org.", ".aero.", ".gov.", ".com.", ".edu.", ".gob.", ".name.", ".ind.",".res.", ".firm."}; 
static const char *invalid_chars[] = {",", "_", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "`", "\"", "/", "\\", "[", "]", "{", "}", "|", "?"}; 
static const char *invalid_conf_and_zone_chars[] = {"_", "~","#", "$", "%", "^", "`","|", "[", "]"}; 
typedef int boolean;
static const boolean _true = 1;
static const boolean _false = 0;
static const int max_buf =  255;
unsigned int already_prctl = 0;
unsigned int zone_count = 0;
unsigned int rldns_response_id;

char *fail_to_memaloc = "\n | rldns : Fatal Error ! Memory Allocation Failure ! |\n";
char *fail_to_setegid = "\n | rldns : Warning ! failed to setegid ! |\n";
char *fail_to_setreuid = "\n | rldns : Warning ! failed to setreuid ! |\n";
char *fail_to_setregid = "\n | rldns : Warning ! failed to setregid ! |\n";
char *fail_to_seteuid = "\n | rldns : Warning ! failed to seteuid ! |\n";
char *fail_to_setuid = "\n | rldns : Warning ! failed to setuid ! |\n";
char *fail_to_setgid = "\n | rldns : Warning ! failed to setgid ! |\n";
char *fail_to_closefd = "\n | rldns : Warning ! failed to close file descriptor ! |\n";
char *fail_to_set_logs = "\n | rldns : Warning ! failed to prepare log files ! You need to run rldns as root  ! |\n";
char *fail_nonblock = "\n | rldns : Warning ! failed to create a non blocking socket for handling multiple connection ! |\n";
char *no_config = "\n | rldns : Fatal Error ! rldns.conf not found ! exit ! |\n";
char *sock_fail = "\n  | rldns : Fatal Error ! failed to create socket ! exit ! |\n";
char *no_user = "\n  | rldns : Fatal Error ! no rldns user ! please adduser rldns first ! exit ! |\n";
char *fail_reuseaddr = "\n | rldns : Warning ! failed to setsockopt for reuseaddr ! |\n";
char *fail_bind = "\n | rldns : Fatal Error ! failed to bind socket ! |\n";
char *no_zones = "\n | rldns : Fatal Error !  no zone files found, please add domain zone file(s) ! |\n";
char *no_zonepath = "\n | rldns : Fatal Error !  incorrect zone path , please check your zone setting at rldns.conf ! |\n";
char *failed_prctl = "\n | rldns : Warning ! prctl failed to control cr4 ! |\n";
char *rldns_on_x86 = "\t[+] preparing to run rldns on x86 machine\n";
char *rldns_on_x86_64 = "\t[+] preparing to run rldns on x86_64 machine\n";
char *rldns_on_arm = "\t[+] preparing to run rldns on arm machine\n";
char *rldns_on_unsupported = "\n | rldns :  Fatal Error ! sorry rldns can not run on unsupported machine ! exit !!!\n";
char *rldns_error_config = "\n | rldns :  Fatal Error ! There's error on your rldns.conf, invalid character found ! Please check your config ! exit !!!\n";
char *rldns_error_zone = "\n | rldns :  Fatal Error ! There's error on your zone files, invalid character found ! Please check your zone setting ! exit !!!\n";
char *incorrect_zone_syntax = "\n | rldns :  Fatal Error ! Incorrect zone syntax ! Please check your zone file setting ! rldns exit !!!\n";
char *rldns_main_banner = "\t[+] rldns 1.4 -  developed by : Antonius (w1sdom) - (c) Copyright by bluedragonsec.com all rights reserved\n";
char *rldns_already_run = "\n | rldns : Fatal Error !  rldns already running ! Please kill rldns process before running new instance ! |\n";
/** eof vars **/

const char *rldns_path = "/usr/local/rldns/";
#endif
