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
#ifndef _MPOLSR_PROCESS_PACKAGE
#define _MPOLSR_PROCESS_PACKAGE

#include "mp_olsr_protocol.h"
#include "mp_packet.h"
#include "mp_parse_msg.h"
namespace MPOLSRv2{

void olsr_init_package_process(struct olsrv2 *);

void olsr_process_received_hello(struct olsrv2 *, struct message_header *,
                 IP_ADDR *,
                 union olsr_ip_addr *);

void olsr_process_received_tc(struct olsrv2 *, struct message_header *,
                  IP_ADDR *,
                  union olsr_ip_addr *);

void olsr_process_received_ma(struct olsrv2 *, struct message_header *,
                  IP_ADDR *,
                  union olsr_ip_addr *);
}

#endif
