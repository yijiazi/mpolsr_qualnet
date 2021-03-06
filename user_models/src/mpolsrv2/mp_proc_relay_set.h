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
#ifndef __MP_PROC_RELAY_SET_H
#define __MP_PROC_RELAY_SET_H

#include <time.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

#include "mp_olsr.h"
namespace MPOLSRv2{

typedef struct olsr_relay_tuple
{
  union olsr_ip_addr RS_if_addr;
}OLSR_RELAY_TUPLE;


/* function prototypes */
//#if defined __cplusplus
//extern "C" {
//#endif
  void print_relay_set(struct olsrv2 *);
//#if defined __cplusplus
//}
//#endif

void init_relay_set(struct olsrv2 *);


olsr_u16_t get_local_assn(struct olsrv2 *);

void increment_local_assn(struct olsrv2 *);

olsr_bool proc_relay_set(struct olsrv2 *, union olsr_ip_addr *);

void delete_relay_set_handler_for_ms_timeout(struct olsrv2 *olsr,
                         OLSR_LIST* retList);
OLSR_LIST *search_relay_set(struct olsrv2 *, union olsr_ip_addr *);
olsr_bool search_relay_set_for_exist(struct olsrv2 *olsr,
                     union olsr_ip_addr *neighbor_iface_addr);
int check_relay_set_for_match_num_entry(struct olsrv2 *olsr,
                    union olsr_ip_addr *neighbor_iface_addr);
void delete_relay_set(struct olsrv2 *olsr,
              union olsr_ip_addr *neighbor_iface);
}
#endif
