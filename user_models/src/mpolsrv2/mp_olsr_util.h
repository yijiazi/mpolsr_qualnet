/************************************************************************************************
*	Copyright (C) 2010									*
*	    Multipath Extension of MP-OLSRv2
					by 			Jiazi Yi (Ecole Polytechnique Nantes,France) jiazi.yi@univ-nantes.fr		*
*												
*    	This program is distributed in the hope that it will be useful,				*
*    	but WITHOUT ANY WARRANTY; without even the implied warranty of				*
*    	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 					*
*************************************************************************************************
*************************************************************************************************/

/*
 *
 * Copyright (c) 2006, Graduate School of Niigata University,
 *                                         Ad hoc Network Lab.
 * Developer:
 *  Yasunori Owada  [yowada@net.ie.niigata-u.ac.jp],
 *  Kenta Tsuchida  [ktsuchi@net.ie.niigata-u.ac.jp],
 *  Taka Maeno      [tmaeno@net.ie.niigata-u.ac.jp],
 *  Hiroei Imai     [imai@ie.niigata-u.ac.jp].
 * Contributor:
 *  Keita Yamaguchi [kyama@net.ie.niigata-u.ac.jp],
 *  Yuichi Murakami [ymura@net.ie.niigata-u.ac.jp],
 *  Hiraku Okada    [hiraku@ie.niigata-u.ac.jp].
 *
 * This software is available with usual "research" terms
 * with the aim of retain credits of the software.
 * Permission to use, copy, modify and distribute this software for any
 * purpose and without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies,
 * and the name of NIIGATA, or any contributor not be used in advertising
 * or publicity pertaining to this material without the prior explicit
 * permission. The software is provided "as is" without any
 * warranties, support or liabilities of any kind.
 * This product includes software developed by the University of
 * California, Berkeley and its contributors protected by copyrights.
 */
#ifndef __MPOLSR_UTIL_H
#define __MPOLSR_UTIL_H

//WIN FIX
//#include<sys/time.h>
#include "mp_olsr_types.h"
#include "mp_olsr_common.h"

#include "mp_olsr.h"

namespace MPOLSRv2{

#if defined __cplusplus
//extern "C" {
#endif

char * olsr_niigata_ip_to_string(struct olsrv2* olsr, union olsr_ip_addr *);
void qualnet_print_clock_in_second(qualnet_time_t, char []);

void ConvertIpv4AddressToString(olsr_u32_t ipAddress,char *addressString);
void ConvertIpv6AddressToString(struct in6_addr_qualnet* ipv6Address,
                                char* interfaceAddr,
                                olsr_bool ipv4EmbeddeAddr);
#if defined __cplusplus
//}
#endif

olsr_bool equal_netmask(struct olsrv2* olsr,const union hna_netmask *, const union hna_netmask *);
olsr_32_t cmp_ip_addr(struct olsrv2* olsr, const union olsr_ip_addr *, const union olsr_ip_addr *);

char* convert_to_char_from_time(time_t time);
void set_current_time(struct olsrv2 *, olsr_time_t *);
void get_current_time(struct olsrv2 *, olsr_time_t *);
void update_time(olsr_time_t *, olsr_32_t);
olsr_time_t olsr_max_time(olsr_time_t, olsr_time_t);
olsr_time_t olsr_min_time(olsr_time_t, olsr_time_t);
L_STATUS get_link_status(olsr_time_t, olsr_time_t, olsr_time_t, olsr_time_t);
L_STATUS get_neighbor_status(olsr_time_t *, olsr_time_t *);

}
#endif
