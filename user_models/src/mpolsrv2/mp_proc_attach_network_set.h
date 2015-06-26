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
#ifndef __MP_PROC_ATTACH_SET_H
#define __MP_PROC_ATTACH_SET_H

#include <time.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

#include "mp_olsr.h"
namespace MPOLSRv2{


typedef struct olsr_attached_tuple
{
  union olsr_ip_addr AN_net_addr;
  union olsr_ip_addr AN_gw_addr;
  olsr_u16_t AN_seq;
  olsr_time_t AN_time;
  olsr_u8_t AN_prefix_length;
}OLSR_ATTACHED_TUPLE;

/* function prototypes */
#if defined __cplusplus
//extern "C" {
#endif
  void print_attached_set(struct olsrv2 *);
#if defined __cplusplus
//}
#endif

void init_attached_set(struct olsrv2 *);
void proc_attached_set(struct olsrv2 *,
               const union olsr_ip_addr *,
               olsr_u8_t,
               const union olsr_ip_addr *,
               olsr_u16_t);

void delete_attached_set_for_timeout(struct olsrv2 *);
void add_attached_network_set(struct olsrv2 *);
}
#endif
