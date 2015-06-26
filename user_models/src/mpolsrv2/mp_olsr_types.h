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

#ifndef __MPOLSR_TYPES_H
#define __MPOLSR_TYPES_H

/* types */
#if defined (WIN32) || defined (_WIN32) || defined (__WIN64)
    #include <winsock2.h>

#else
    #include <sys/types.h>
#endif
namespace MPOLSRv2{


typedef enum
{
    OLSR_FALSE = 0,
    OLSR_TRUE
}olsr_bool;


#if defined linux

typedef u_int8_t        olsr_u8_t;
typedef u_int16_t       olsr_u16_t;
typedef u_int32_t       olsr_u32_t;
typedef int8_t          olsr_8_t;
typedef int16_t         olsr_16_t;
typedef int32_t         olsr_32_t;

#elif defined __FreeBSD__ || defined __NetBSD__

typedef uint8_t         olsr_u8_t;
typedef uint16_t        olsr_u16_t;
typedef uint32_t        olsr_u32_t;
typedef int8_t          olsr_8_t;
typedef int16_t         olsr_16_t;
typedef int32_t         olsr_32_t;

#elif defined (WIN32) || defined (_WIN32) || defined (__WIN64)

typedef unsigned char   olsr_u8_t;
typedef unsigned short  olsr_u16_t;
typedef unsigned int    olsr_u32_t;
typedef char            olsr_8_t;
typedef short           olsr_16_t;
typedef int             olsr_32_t;

#else
//#       error "Unsupported system"
typedef unsigned char   olsr_u8_t;
typedef unsigned short  olsr_u16_t;
typedef unsigned int    olsr_u32_t;
typedef char            olsr_8_t;
typedef short           olsr_16_t;
typedef int             olsr_32_t;
#endif


/* IPv6 address format in6_addr */

struct in6_addr_qualnet
{
#if defined _NETINET_IN_H_
  union
  {
    olsr_u8_t    u6_addr8[16];
    olsr_u16_t   u6_addr16[8];
    olsr_u32_t   u6_addr32[4];
  } u6_addr;
#define s6_addr_32   u6_addr.u6_addr32
#define s6_addr_16   u6_addr.u6_addr16
#define s6_addr_8 u6_addr.u6_addr8
#else
  union
  {
    olsr_u8_t    u6_addr8[16];
    olsr_u16_t   u6_addr16[8];
    olsr_u32_t   u6_addr32[4];
  } in6_u;
#define s6_addr_32   in6_u.u6_addr32
#define s6_addr_16   in6_u.u6_addr16
//#define s6_addr in6_u.u6_addr8
#define s6_addr_8 in6_u.u6_addr8
#endif
};

#ifdef __WIN64                                      // 64bit Windows
typedef _int64          int_64;
#elif defined (__LP64__) || ( __WORDSIZE == 64 )    //64bit Unix/MacOS X
typedef long            int_64;
#elif defined (WIN32) || defined (_WIN32)           // 32bit Windows
typedef _int64          int_64;
#elif defined (__unix)                              // 32bit Unix
typedef long long       int_64;
#else
typedef long long       int_64;
#endif

typedef int_64 olsr_64_t;


union olsr_ip_addr
{
  olsr_u32_t v4;
  struct in6_addr_qualnet v6;
};

union hna_netmask
{
  olsr_u32_t v4;
  olsr_u16_t v6;
};
}

#endif
