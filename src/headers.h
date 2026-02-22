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
 
#ifndef _headers_h_
#define _headers_h_
 
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)  
	#include <sys/prctl.h>
#endif
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#ifndef CONFIG
#	define CONFIG "rldns.conf"
#endif
#ifndef PACKET_SIZE
#	define PACKET_SIZE 512
#endif
#ifndef MAX_ZONE_FILE_LINE_LENGTH
#	define MAX_ZONE_FILE_LINE_LENGTH 256
#endif
#ifndef MAX_A_LENGTH_ALLOWED
#	define MAX_A_LENGTH_ALLOWED 62
#endif
#ifndef header_length
#	define header_length 13
#endif
#ifndef MAX_NS_LENGTH
#	define MAX_NS_LENGTH 63
#endif
#ifndef MAX_MX_LENGTH
#	define MAX_MX_LENGTH 63
#endif
#ifndef MAX_CNAME_LENGTH
#	define MAX_CNAME_LENGTH 10
#endif
#ifndef MAX_IP_LENGTH
#	define MAX_IP_LENGTH 16
#endif
#ifndef A_ONLY
#	define A_ONLY "a_name_without_tld"
#endif
#ifndef A_TLD
#	define A_TLD "a_name_with_tld"
#endif
#ifndef RET_NS_IP
#	define RET_NS_IP "ns_resolve_ip_needed"
#endif
#ifndef RET_NO_ANSWER
#	define RET_NO_ANSWER "return no answer"
#endif
#ifndef A_DEFAULT
#	define A_DEFAULT "a_name_returned"
#endif
#ifndef MOD_BASIC
#	define MOD_BASIC "basic mode"
#endif
#ifndef MOD_NS
#	define MOD_NS "ns mode"
#endif
#ifndef LOG_IP
#	define LOG_IP "log ip"
#endif
#if defined(__i386__)  || defined(__i486__)  || defined(__i586__)  || defined(__i686__) || defined(__ARM_ARCH_7__) ||  defined(__ARM_ARCH_7A__) ||  defined(__ARM_ARCH_7R__) ||  defined(__ARM_ARCH_7S__) ||  defined(__ARM_ARCH_7M__)
static const int divide_by = 4;
#elif defined(__x86_64__) || defined(__amd64__)
static const int divide_by = 8;
#endif

#endif
