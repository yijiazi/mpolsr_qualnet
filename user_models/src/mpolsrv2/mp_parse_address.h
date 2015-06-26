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

#ifndef MP_PARSE_ADDRESS_H
#define MP_PARSE_ADDRESS_H

#include "mp_olsr_conf.h"
//#include "def.h"
#include "mp_parse_tlv.h"


#include "mp_olsr_types.h"
//#include <sys/socket.h>
namespace MPOLSRv2{

#define BYTE_BIT 8
struct address_tuple
{
  union olsr_ip_addr ip_addr;
  int ip_version;
  struct tlv_tuple *addr_tlv;

  struct address_tuple *next;
};

struct address_list
{
  union olsr_ip_addr ip_addr;
  int index;
  struct address_list *next;
};

struct address_block_info
{
  olsr_u8_t num_addr;
  olsr_u8_t head_length;
  union olsr_ip_addr head;
  olsr_u8_t tail_length;
  union olsr_ip_addr tail;
  olsr_u8_t mid_length;
  olsr_u8_t no_tail;
  olsr_u8_t zero_tail;
};

//struct address_tuple *address_tlv_block_entries[MAX_ADDR_TLV_BLOCK_ENTRIES];
//struct address_tuple *local_interface_block_entry;


void init_parse_address(struct olsrv2 *);
char *parse_address(struct olsrv2 *, struct address_list **, char *, char *);
void free_address_list(struct address_list *);
void create_address_entry(struct olsrv2 *,
              struct address_list *, struct tlv_tuple_local *,
              struct address_tuple**);

void free_all_address_entries(struct olsrv2 *);
}
#endif
