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
#ifndef __MPOLSR_ADDRESS_COMPRESS_H
#define __MPOLSR_ADDRESS_COMPRESS_H

#include "mp_olsr_common.h"
#include "mp_olsr_list.h"
#include "mp_olsr.h"
#include "mp_pktbuf.h"

namespace MPOLSRv2{


#define LOCAL_ADDRESS_BLOCK 255
enum
{
  //NOT_COMPRESS,
  SIMPLE_COMPRESS
};

typedef struct block_data
{
  union olsr_ip_addr iface_addr;
  olsr_u8_t link_status;
  olsr_u8_t other_if;
  olsr_u8_t MPR_Selection;
  olsr_u8_t Prefix_Length;
  olsr_u8_t other_neigh;


  olsr_bool covered;
} BLOCK_DATA;

typedef struct base_address
{
  olsr_u32_t size;
  BLOCK_DATA *data;
} BASE_ADDRESS;

typedef struct prefix_str
{
  olsr_u32_t prefix_size;
  olsr_u8_t *prefix;

  olsr_u32_t union_num;
} PREFIX;

typedef struct address_block
{
  PREFIX prefix;
  OLSR_LIST block;
} ADDRESS_BLOCK;


/* function prototypes */
void address_compress(struct olsrv2 *, olsr_pktbuf_t *,
    olsr_u8_t, olsr_u8_t, union olsr_ip_addr *);

void create_attached_network_address_block(struct olsrv2 *,
                       olsr_pktbuf_t *,
                       olsr_u8_t ,
                       olsr_u8_t ,
                       union olsr_ip_addr *);
}

#endif
