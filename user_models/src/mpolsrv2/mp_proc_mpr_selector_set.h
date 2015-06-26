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
#ifndef __MP_PROC_MPR_SELECTOR_SET_H
#define __MP_PROC_MPR_SELECTOR_SET_H

#include <time.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

#include "mp_olsr.h"
namespace MPOLSRv2{


typedef struct olsr_mpr_selector_tuple
{
  union olsr_ip_addr MS_neighbor_if_addr;
  olsr_time_t MS_time;
}OLSR_MPR_SELECTOR_TUPLE;


/* function prototypes */
#if defined __cplusplus
//extern "C" {
#endif
void print_mpr_selector_set(struct olsrv2 *);
#if defined __cplusplus
//}
#endif

void init_mpr_selector_set(struct olsrv2 *);
void proc_mpr_selector_set(struct olsrv2 *,
               union olsr_ip_addr *);
OLSR_LIST* delete_mpr_selector_set_for_timeout(struct olsrv2 *);

void delete_mpr_selector_set(struct olsrv2 *olsr,
                 union olsr_ip_addr* addr);
OLSR_LIST* delete_mpr_selector_set_for_linkbreakage(struct olsrv2 *olsr);
}
#endif
