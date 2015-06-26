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

#ifndef MPOLSR_PARSE_MSG_H
#define MPOLSR_PARSE_MSG_H

//#include "mp_def.h"
#include "mp_olsr_protocol.h"
#include "mp_olsr_conf.h"

#include "mp_proc_rcv_msg_set.h"
#include "mp_proc_proc_set.h"
#include "mp_proc_forward_set.h"
#include "mp_parse_tlv.h"
#include "mp_parse_address.h"

namespace MPOLSRv2{

#define PROMISCOUS 0xffffffff
#define IPV4_MESSAGE_HEADER_SIZE 12
#define IPV6_MESSAGE_HEADER_SIZE 24

typedef void (*parse_function_type) (struct olsrv2 *,
    struct message_header *,
    union olsr_ip_addr *,
    union olsr_ip_addr *);  // XXX:hre , olsr_u8_t *);

struct parse_function_entry
{
  olsr_u32_t type;      /* ex. type = PROMISCOUS */
  int is_forward;       /* 1: do forwading ; 0: not forwarding */
  parse_function_type function;

  struct parse_function_entry *next;

};


/* this is first pointer to parse_function */
//struct parse_function_entry *parse_functions;

/* function prototype */
#if defined __cplusplus
//extern "C"
//{
#endif
  void olsr_init_parser(struct olsrv2 *);

  void parse_packet(struct olsrv2 *, char *, olsr_u16_t,
      IP_ADDR *,
      union olsr_ip_addr);

#if defined __cplusplus
//}
#endif

void olsr_parser_add_function(struct olsrv2 *, parse_function_type, olsr_u32_t, int);

int olsr_parser_remove_function(struct olsrv2 *, parse_function_type, olsr_u32_t, int);

void olsr_input(int, void *);
}
#endif
