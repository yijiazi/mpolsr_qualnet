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
#ifndef __MP_PROC_LINK_SET_H
#define __MP_PROC_LINK_SET_H

#include <time.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

#include "mp_olsr.h"
namespace MPOLSRv2{

typedef struct olsr_link_tuple
{
  union olsr_ip_addr L_local_iface_addr;
  union olsr_ip_addr L_neighbor_iface_addr;
  olsr_time_t L_SYM_time;
  olsr_time_t L_ASYM_time;
  olsr_time_t L_time;
  olsr_time_t L_LOST_LINK_time;
  double L_link_quality;
  double validity_time;
  double interval_time;
  olsr_u8_t L_willingness;
  olsr_u8_t h_count;
  olsr_bool L_link_pending;
}OLSR_LINK_TUPLE;


/* function prototypes */
#if defined __cplusplus
//extern "C" {
#endif
void print_link_set(struct olsrv2 *);

void proc_link_layer_notification(struct olsrv2 *,
                  union olsr_ip_addr );

#if defined __cplusplus
//}
#endif

void check_link_hysteresis(struct olsrv2*);
void init_link_set(struct olsrv2 *);
void proc_link_set(struct olsrv2 *,
           union olsr_ip_addr *,
           union olsr_ip_addr *,
           olsr_u8_t, olsr_u8_t,
           double,
           double);
void delete_link_set_for_timeout(struct olsrv2 *);
OLSR_LIST *search_link_set(struct olsrv2 *, union olsr_ip_addr *);
OLSR_LIST *search_link_set_for_symmetric(struct olsrv2 *, union olsr_ip_addr *);
olsr_bool search_link_set_for_symmetric_exist(struct olsrv2 *olsr,
                          union olsr_ip_addr *neighbor_addr);
OLSR_LIST *search_link_set_local(struct olsrv2 *,
              union olsr_ip_addr *,
              union olsr_ip_addr *);
olsr_bool search_link_set_local_for_exist(struct olsrv2 *,
                      union olsr_ip_addr *,
                      union olsr_ip_addr *);
int lookup_link_status(struct olsrv2 *, union olsr_ip_addr *);
OLSR_LINK_TUPLE *lookup_link_set(struct olsrv2 *,union olsr_ip_addr *);

}
#endif
