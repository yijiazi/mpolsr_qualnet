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
#ifndef __MP_PROC_ROUTING_SET_H
#define __MP_PROC_ROUTING_SET_H

#include <time.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

#include "mp_olsr.h"
namespace MPOLSRv2{


typedef struct olsr_routing_tuple
{
  union olsr_ip_addr R_dest_iface_addr;
  union olsr_ip_addr R_next_iface_addr;
  olsr_u8_t R_prefix_length;
  olsr_u16_t R_dist;
  union olsr_ip_addr R_iface_addr;
}OLSR_ROUTING_TUPLE;


/* function prototypes */

#if defined __cplusplus
//extern "C" {
#endif
void print_routing_set(struct olsrv2 *);

OLSR_LIST *search_routing_set_for_next_and_dest(
                   struct olsrv2 *,
                   union olsr_ip_addr *,
                   const union olsr_ip_addr *);

OLSR_LIST *search_routing_set_old_for_next_and_dest(
                   struct olsrv2 *,
                   union olsr_ip_addr *,
                   const union olsr_ip_addr *);

void insert_routing_set_old(
                struct olsrv2 *,
                const union olsr_ip_addr *,
                const union olsr_ip_addr *,
                olsr_u8_t,  //prefix length
                olsr_u16_t,
                const union olsr_ip_addr *);

void delete_routing_set_old(struct olsrv2 *olsr,
                  union olsr_ip_addr *,
                  const union olsr_ip_addr *);

void insert_routing_set(struct olsrv2 *,
            union olsr_ip_addr *,
            const union olsr_ip_addr *,
            olsr_u8_t,
            olsr_u16_t,
            const union olsr_ip_addr *);

#if defined __cplusplus
//}
#endif

void init_routing_set(struct olsrv2 *);

olsr_bool check_recalculate_routing_set(struct olsrv2 *);
void reset_recalculate_routing_set(struct olsrv2 *);

void proc_routing_set(struct olsrv2 *);

}
#endif
