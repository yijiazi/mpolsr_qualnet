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
#ifndef __MP_OLSR_TLV_COMPLESS_H
#define __MP_OLSR_TLV_COMPLESS_H

#include "mp_pktbuf.h"
namespace MPOLSRv2{

typedef struct base_tlv
{
  olsr_u8_t tlv_type;
  olsr_u8_t tlv_semantics;
  olsr_u8_t tlv_length;
  olsr_u8_t index_start;
  olsr_u8_t index_stop;
  olsr_u8_t *value;
} BASE_TLV;

/* function prototypes */
void build_tlv_block_tc(olsr_pktbuf_t *);
void build_tlv_block_local(olsr_pktbuf_t *);
void build_tlv_block_for_index_hello(olsr_pktbuf_t *, BASE_ADDRESS *,
    olsr_u32_t);
void build_tlv_block_for_index_local(olsr_pktbuf_t *, BASE_ADDRESS *,
                     olsr_u32_t);
void build_tlv_local_by_list(void *,olsr_pktbuf_t *, OLSR_LIST *);
void build_tlv_hello_by_list(void *, olsr_pktbuf_t *, OLSR_LIST *);

void print_other_neigh_status(olsr_u8_t);
void print_link_status(olsr_u8_t);
void print_interface(olsr_u8_t);
void print_mpr_selection(olsr_bool);

void
build_tlv_attached_network_by_list(void *olsr, olsr_pktbuf_t *, OLSR_LIST *);
void
build_tlv_block_for_index_attached_network(olsr_pktbuf_t *,
                 BASE_ADDRESS *,
                 olsr_u32_t );
}

#endif /* __OLSR_TLV_COMPLESS_H */
