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
#ifndef __MPOLSR_COMMON_H
#define __MPOLSR_COMMON_H

//WIN FIX Start
#if defined (WIN32) || defined (_WIN32) || defined (__WIN64)
    #include <sys/timeb.h>
    //#include <varargs.h>

    #ifndef __func__
        #define __func__ __FUNCTION__
    #endif

#else
    #include<sys/time.h>
    #include <stdarg.h>
#endif
#include "mp_olsr_types.h"

namespace MPOLSRv2{


typedef struct timeval olsr_timeval_t;

typedef struct timeval linux_time_t;
//Compilation Fix
//typedef long long qualnet_time_t;
typedef int_64 qualnet_time_t;

typedef qualnet_time_t olsr_time_t;

#define OLSRv2_NANO_SECOND              ((qualnet_time_t) 1)
#define OLSRv2_MICRO_SECOND             (1000 * OLSRv2_NANO_SECOND)
#define OLSRv2_MILLI_SECOND             (1000 * OLSRv2_MICRO_SECOND)
#define OLSRv2_SECOND                   (1000 * OLSRv2_MILLI_SECOND)
#define OLSRv2_MINUTE                   (60 * OLSRv2_SECOND)
#define OLSRv2_HOUR                     (60 * OLSRv2_MINUTE)
#define OLSRv2_DAY                      (24 * OLSRv2_HOUR)


#define OLSR_INVALID_INTERFACE 255

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define v_time 6 //second because of consistency


//packet bb-02

#define NO_PSEQNUM  0x01
#define PACKET_TLV  0x02

#define NO_ORIG_HOP 0x03

#define NO_TAIL 0x80
#define ZERO_TAIL 0x80

#define GET_HEAD_LENGTH 0x7f
#define GET_TAIL_LENGTH 0x7f

#define USER_BIT     0x80
#define TLV_PROT     0x40

#define EXTENDED     0x01
#define NO_VALUE     0x02
#define NO_INDEX     0x04
#define SINGLE_INDEX 0x08
#define MULTI_VALUE  0x10
#define ALL_ZERO    0x00


typedef enum
  {
    Fragmentation,
    Content_Sequence_Number,
    Willingness,
    Validity_Time,
    Interval_Time,
    queuelen		//codexxx
  }OLSR_MSG_TLV_TYPES;

typedef enum
  {
    PREFIX_LENGTH,
    Link_Status,
    Other_If,
    MPR_Selection,
    Other_Neigh,
    Gate_Way,
   // R_etx   // codexxx
  }OLSR_TLV_TYPES;


typedef enum
  {
    LOST,
    SYMMETRIC,
    ASYMMETRIC,
    UNSPEC,
  }L_STATUS;

}
#endif
