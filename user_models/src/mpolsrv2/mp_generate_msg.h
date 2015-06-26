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
#ifndef _MPOLSR_GEN_MSG
#define _MPOLSR_GEN_MSG

#include "mp_pktbuf.h"
#include "mp_olsr_types.h"

namespace MPOLSRv2{


#define STDOUT_PULSE_INT    (0.6)

struct parameter
{

  struct olsrv2 *olsr;

  union olsr_ip_addr *ifp;
  /* Common parameter structure which is used for MA, TC and HELLO */
  /* ADD vars if you want */
};

union tlv_value
{
  olsr_u8_t val_8;
  olsr_u16_t val_16;
  olsr_u32_t val_32;
  /* ADD if new value is defined */
};
/*
typedef struct generate_func_param{
  struct olsrv2 *olsr;
  struct interface *ifp;
}GENERATE_FUNC_PARAM;
*/
/* Functions */

void build_message_header(struct olsrv2 *,
    olsr_pktbuf_t *pktbuf, const olsr_u16_t msg_size,
    const int msg_type, const union olsr_ip_addr* originator,
    const int ttl, const int hopcount, const int message_seq_no);

//void generate_hello_msg(GENERATE_FUNC_PARAM *);

//void generate_tc_msg(GENERATE_FUNC_PARAM *);

olsr_u8_t *build_message_tlv(int msg_type, int tlv_type, int *size,
    union tlv_value *tlv_value, int tlv_length);



#ifdef __cplusplus
//extern "C"{
#endif

void build_hello_msg(struct olsrv2 *olsr, olsr_pktbuf_t *pktbuf,
    union olsr_ip_addr *local_iface_addr
    );
void build_tc_msg(struct olsrv2 *olsr, olsr_pktbuf_t *pktbuf,
    union olsr_ip_addr *local_iface_addr
    );
#ifdef __cplusplus
//}
#endif

}
#endif

