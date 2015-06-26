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
#ifndef _MPOLSR_UTIL_INLINE_
#define _MPOLSR_UTIL_INLINE_

#include "mp_olsr_util.h"

namespace MPOLSRv2{

/**
 *
 */
static //inline
void
olsr_ip4_copy(union olsr_ip_addr* dst, const union olsr_ip_addr* src)
{
    olsr_u32_t* x = (olsr_u32_t*)dst;
    const olsr_u32_t* y = (olsr_u32_t*)src;
    *x = *y;
}

/**
 *
 */
static //inline
void
olsr_ip6_copy(union olsr_ip_addr* dst, const union olsr_ip_addr* src)
{
    olsr_u32_t* x = (olsr_u32_t*)dst;
    const olsr_u32_t* y = (const olsr_u32_t*)src;

    *x = *y;
    *(x + 1) = *(y + 1);
    *(x + 2) = *(y + 2);
    *(x + 3) = *(y + 3);
}

/**
 *
 */
static //inline
void
olsr_ip_copy(struct olsrv2 *olsr,
         union olsr_ip_addr* dst, const union olsr_ip_addr* src)
{
//Fix for Solaris bus error
   memcpy(dst, src, olsr->olsr_cnf->ipsize);
    /*if (olsr->olsr_cnf->ip_version == AF_INET)
    olsr_ip4_copy(dst, src);
    else
    olsr_ip6_copy(dst, src);*/
}

static //inline
olsr_bool equal_ip_addr(struct olsrv2 *olsr,
            const union olsr_ip_addr* x,
            const union olsr_ip_addr* y)
{
    if(olsr->olsr_cnf->ip_version == AF_INET)
    {
    return (olsr_bool)(x->v4 == y->v4);
    }
    else if(olsr->olsr_cnf->ip_version == AF_INET6)
    {
    if(memcmp(&x->v6.s6_addr_8, &y->v6.s6_addr_8, sizeof(struct in6_addr_qualnet)) == 0)
    {
        return OLSR_TRUE;
    }
    else
    {
        return OLSR_FALSE;
    }
    }
    else
    {
    olsr_error("Un known ip_version");
    }

    return OLSR_FALSE;
}

static //inline
olsr_bool own_ip_addr(struct olsrv2 *olsr,
              const union olsr_ip_addr* x)
{
    olsr_u8_t i;


    if(olsr->olsr_cnf->ip_version == AF_INET)
    {
    for(i=0; i<olsr->iface_num; i++)
    {
        if(x->v4 == olsr->iface_addr[i].v4)
        {
        return OLSR_TRUE;
        }
    }
    }
    else if(olsr->olsr_cnf->ip_version == AF_INET6)
    {
    for(i=0; i<olsr->iface_num; i++)
    {
        if(memcmp(&x->v6.s6_addr_8, &olsr->iface_addr[i].v6.s6_addr_8, sizeof(struct in6_addr_qualnet)) == 0)
        {
        return OLSR_TRUE;
        }
    }
    }
    else
    {
    olsr_error("Un known ip_version");
    }

    return OLSR_FALSE;
}


static //inline
olsr_32_t
//double
olsr_cmp_time(olsr_time_t a, olsr_time_t b)
{
  char time[30];
  qualnet_print_clock_in_second(a-b, time);
  return atoi(time);
//return atof(time);
}


inline
static
char *get_bytes(char *msg_ptr, int bytes, void *value)
{
  switch(bytes)
    {
    case 0:
      break;
    case sizeof(olsr_u8_t):
      {
    olsr_u8_t tmpVal;
    tmpVal = *msg_ptr++;
    *(olsr_u8_t *)value = tmpVal;
    break;
      }
    case sizeof(olsr_u16_t):
      {
    olsr_u16_t tmpVal;
//Fix for Solaris bus error
    memcpy(&tmpVal, msg_ptr, sizeof(tmpVal));
    //tmpVal = *(olsr_u16_t *)msg_ptr;
    msg_ptr += bytes;
    *(olsr_u16_t *)value = tmpVal;
    break;
      }
    case sizeof(olsr_u32_t):
      {
    olsr_u32_t tmpVal;
//Fix for Solaris bus error
    memcpy(&tmpVal, msg_ptr, sizeof(tmpVal));
    //tmpVal = *(olsr_u32_t *)msg_ptr;
    msg_ptr += bytes;
    *(olsr_u32_t *)value = tmpVal;
    break;
      }
    default:
      memcpy(value, msg_ptr, bytes);
      msg_ptr += bytes;
      break;
    }

  return msg_ptr;
}

inline static olsr_bool check_length_over_limit(char *ptr, char *limit, olsr_u16_t length)
{
  if(ptr + length > limit)
    return OLSR_FALSE;
  return OLSR_TRUE;
}
}
#endif
