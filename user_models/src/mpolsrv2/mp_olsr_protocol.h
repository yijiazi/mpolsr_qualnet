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
#ifndef __PROTOCOLS_MPOLSR_H
#define __PROTOCOLS_MPOLSR_H

#include "mp_olsr_types.h"
namespace MPOLSRv2{


/* Port for OLSR to use */

#define OLSRPORT       698

/* Default IPv6 multicast addresses */

#define OLSR_IPV6_MCAST_SITE_LOCAL "ff05::15"
#define OLSR_IPV6_MCAST_GLOBAL     "ff0e::1"

#define OLSR_HEADERSIZE (sizeof(olsr_u16_t) + sizeof(olsr_u16_t))


/*
 *Emission Intervals
 */

#define HELLO_INTERVAL        2
#define REFRESH_INTERVAL      2
#define TC_INTERVAL           5
#define ORIG_INTERVAL         TC_INTERVAL

/*
 * For Link Layer Nortification
 * TC or Hello MAY generate additional message.
 */
/*
#define TC_MIN_INTERVAL       TC_INTERVAL / 4
#define HELLO_MIN_INTERVAL    0.5
*/

/*
 *Holding Time
 */
/*
#define NEIGHB_HOLD_TIME      3 * REFRESH_INTERVAL
#define TOP_HOLD_TIME         3 * TC_INTERVAL
#define DUP_HOLD_TIME         30
#define MID_HOLD_TIME         3 * MID_INTERVAL
#define HNA_HOLD_TIME         3 * HNA_INTERVAL
#define MA_HOLD_TIME          3 * MA_INTERVAL

//#define MS_HOLD_TIME          DUP_HOLD_TIME
#define MS_HOLD_TIME         NEIGHB_HOLD_TIME

#define AN_HOLD_TIME          DUP_HOLD_TIME
#define AS_HOLD_TIME          DUP_HOLD_TIME

//olsrv2
#define RX_HOLD_TIME DUP_HOLD_TIME
#define P_HOLD_TIME DUP_HOLD_TIME
#define F_HOLD_TIME DUP_HOLD_TIME
*/
/*
 * Scaling factor
 */

#define VTIME_SCALE_FACTOR    0.0625

/*
 *Message Types
 */


#define MID_MESSAGE         3
#define HNA_MESSAGE         4
#define MA_MESSAGE          7


#define HELLO_MESSAGE     5
#define TC_MESSAGE        6

/*
 *Link Hysteresis
 */
#define OLSR_LINK_METRIC  OLSR_TRUE
//#define OLSR_LINK_METRIC  OLSR_FALSE
#define OLSR_HYSTERESIS   OLSR_TRUE
#define HYST_THRESHOLD_HIGH   0.8
#define HYST_THRESHOLD_LOW    0.3
#define HYST_SCALING          0.1

/*
 *Willingness
 */
typedef enum
{
  WILL_NEVER = 0,
  WILL_LOW,
  WILL_DEFAULT = 3,
  WILL_HIGH = 6,
  WILL_ALWAYS
} WILLINGNESS;

/*
 *Redundancy defaults
 */
#define TC_REDUNDANCY         0
#define MPR_COVERAGE          1

/*
 *Misc. Constants
 */
#define MAXJITTER             HELLO_INTERVAL / 4
#define MAX_TTL               0xff

/*
 *Sequence numbering
 */

/* Seqnos are 16 bit values */

#define MAXVALUE 0xFFFF

/* Macro for checking seqnos "wraparound" */
#define SEQNO_GREATER_THAN(s1, s2)                \
        (((s1 > s2) && (s1 - s2 <= (MAXVALUE/2))) \
     || ((s2 > s1) && (s2 - s1 > (MAXVALUE/2))))

/*
 * Macros for comparing and copying IP addresses
 */

//#define COMP_IP(ip1, ip2) (!memcmp(ip1, ip2, ipsize))
#define COMP_IP(ip1, ip2) (!cmp_ip_addr(*ip1, *ip2))

//#define COPY_IP(to, from) memcpy(to, from, ipsize)
#define COPY_IP(to, from) memcpy(to, from, olsr->olsr_cnf->ipsize)


/***********************************************
 *           OLSR packet definitions           *
 ***********************************************/
/*
  packet header
*/

struct packet_header
{
  olsr_u8_t zero;
  olsr_u8_t packet_semantics;
  olsr_u16_t packet_seq_num;
};

/*
  message header
*/

struct message_header
{
  olsr_u8_t message_type;
  olsr_u8_t semantics;
  olsr_u16_t message_size;
  union olsr_ip_addr orig_addr;
  olsr_u8_t ttl;
  olsr_u8_t hop_count;
  olsr_u16_t message_seq_num;
};


#define message_has_originator(m)   (((m)->semantics & 0x01) == 0)
#define message_has_msg_seq_number(m)   (((m)->semantics & 0x01) == 0)
#define message_has_ttl(m)      (((m)->semantics & 0x02) == 0)
#define message_has_hop_count(m)    (((m)->semantics & 0x02) == 0)
#define olsr_message_has_type_indep_seq_number(m) \
    (((m)->semantics & 0x04) == 0)
#define olsr_message_is_forward_unkown_message(m) \
    (((m)->semantics & 0x08) == 0)
}
#endif
