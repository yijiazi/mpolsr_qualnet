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
#ifndef MP_PARSE_TLV_H
#define MP_PARSE_TLV_H

#include "mp_olsr_protocol.h"
//#include "mp_def.h"
#include "mp_olsr.h"
#include "mp_olsr_conf.h"
namespace MPOLSRv2{

struct tlv_tuple
{
  olsr_u8_t type;
  olsr_u16_t length;
  olsr_u32_t value;
  olsr_u8_t *extended_value;
  struct tlv_tuple *next;
};

struct tlv_info
{
  olsr_u8_t type;
  olsr_u8_t semantics;
  olsr_u16_t length;
  //msg type flag
  olsr_u8_t user_bit;
  olsr_u8_t tlv_prot;
  //msg semantics
  olsr_u8_t extended_bit;
  olsr_u8_t no_value_bit;
  olsr_u8_t no_index_bit;
  olsr_u8_t single_index_bit;
  olsr_u8_t multi_value_bit;
};

struct tlv_tuple_local
{
  olsr_u8_t type;
  olsr_u16_t length;
  olsr_u8_t semantics;
  olsr_u8_t multi_value_bit;
  olsr_u8_t number_value;
  olsr_u16_t one_field_size;
  olsr_u8_t index_start;
  olsr_u8_t index_stop;
  olsr_u32_t value;
  olsr_u32_t *multi_value;
  olsr_u8_t *extended_value;
  struct tlv_tuple_local *next;
};

//struct tlv_tuple *message_tlv_entry;

char *parse_message_tlv(struct olsrv2 *, char *);
char *parse_address_tlv(struct olsrv2 *, struct tlv_tuple_local **, char *, char );
void free_message_tlv(struct olsrv2 *);
void free_address_tlv(struct tlv_tuple_local *);
struct tlv_tuple *get_msg_tlv(struct olsrv2 *, int msg_type);
char *parse_packet_tlv(struct olsrv2 *, char *);
}
#endif //PARSE_TLV_H
