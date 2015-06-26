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
/*
**
*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

//WIN FIX
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_olsr.h"
#include "mp_parse_msg.h"
#include "mp_proc_recv_packet.h"
#include "mp_olsr_common.h"
#include "mp_pktbuf.h"
namespace MPOLSRv2{

#define BUF_INIT_SIZE   2048
#define BUF_GROW_SIZE   256

#define IPV4_MODE   (olsr_cnf->ip_version == AF_INET)
#define IPV6_MODE   (olsr_cnf->ip_version == AF_INET6)
#define IP_LEN      (IPV4_MODE ? 4 : 16)

//WIN FIX: Changed code to use olsr types in this file

/*
 *
 */
void
olsr_pktbuf_grow_capa(olsr_pktbuf_t *self)
{
  int new_capa = (int)self->capa + BUF_GROW_SIZE;
  if (self->capa == 0)
    {
      olsr_exit("try to modify read only pktbuf.", 1);
    }
  self->data = (olsr_u8_t *)realloc(self->data, new_capa);
  if (self->data == NULL)
    {
      olsr_exit("cannot allocate memory.", 1);
    }
  self->capa = new_capa;
}

/**
 *
 */
olsr_pktbuf_t *
olsr_pktbuf_alloc(void)
{
  return olsr_pktbuf_alloc_with_capa(BUF_INIT_SIZE);
}

/**
 *
 */
olsr_pktbuf_t *
olsr_pktbuf_alloc_with_capa(const size_t capa)
{
//  olsr_pktbuf_t *r = (olsr_pktbuf_t *)malloc(sizeof(olsr_pktbuf_t));
  olsr_pktbuf_t *r = (olsr_pktbuf_t *)olsr_malloc(sizeof(olsr_pktbuf_t), __FUNCTION__);
  r->capa = capa;
  r->data = (olsr_u8_t *)olsr_malloc(capa, "olsr_pktbuf_t:data");
  r->len = 0;
  r->p = r->data;
  return r;
}

/**
 *
 */
olsr_pktbuf_t *
olsr_pktbuf_alloc_child(olsr_pktbuf_t *buf, size_t len)
{
  if (olsr_pktbuf_remain(buf) < len)
    return NULL;
  olsr_pktbuf_t *r = (olsr_pktbuf_t *)olsr_malloc(sizeof(olsr_pktbuf_t), __FUNCTION__);
  r->capa = 0;
  r->len = len;
  r->data = r->p = buf->p;
  buf->p += len;        // increments the pointer of the parent buffer
  return r;
}

/**
 *
 */
void
olsr_pktbuf_free(olsr_pktbuf_t **self)
{
  if ((*self)->capa > 0)
    free((*self)->data);
  free(*self);
  *self = NULL;
}

/**** append ****/

olsr_bool
olsr_pktbuf_append_u16(olsr_pktbuf_t *self, const olsr_u16_t dt)
{
  olsr_u16_t ndt = htons(dt);
  olsr_u8_t *pdt = (olsr_u8_t *) & ndt;

  while (self->len + 2 > self->capa)
    olsr_pktbuf_grow_capa(self);
  self->data[self->len++] = *pdt++;
  self->data[self->len++] = *pdt;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_append_u32(olsr_pktbuf_t *self, const olsr_u32_t dt)
{
  olsr_u32_t ndt = htonl(dt);
  olsr_u8_t *pdt = (olsr_u8_t *) & ndt;

  while (self->len + 4 > self->capa)
    olsr_pktbuf_grow_capa(self);
  self->data[self->len++] = *pdt++;
  self->data[self->len++] = *pdt++;
  self->data[self->len++] = *pdt++;
  self->data[self->len++] = *pdt;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_append_byte_ary(olsr_pktbuf_t *self,
    const olsr_u8_t * dt, const size_t sz)
{
  while (self->len + sz > self->capa)
    olsr_pktbuf_grow_capa(self);
  memcpy(&self->data[self->len], dt, sz);
  self->len += sz;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_append_ip(struct olsrv2* olsr, olsr_pktbuf_t *self, const union olsr_ip_addr *ip)
{
    struct olsrd_config* olsr_cnf = ((struct olsrv2*)olsr)->olsr_cnf;
  return olsr_pktbuf_append_byte_ary(self, (const olsr_u8_t*)ip, IP_LEN);
}

olsr_bool
olsr_pktbuf_append_pktbuf(olsr_pktbuf_t *self, const olsr_pktbuf_t *src)
{
  return olsr_pktbuf_append_byte_ary(self, src->data, src->len);
}

/**** put ****/

olsr_bool
olsr_pktbuf_put_u8(olsr_pktbuf_t *self, size_t idx, const olsr_u8_t dt)
{
  assert(self->len > idx);
  self->data[idx] = dt;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_put_u16(olsr_pktbuf_t *self, size_t idx, const olsr_u16_t dt)
{
  const olsr_u16_t ndt = htons(dt);
  olsr_u8_t *pdt = (olsr_u8_t *) & ndt;

  assert(self->len > idx);
  self->data[idx++] = *pdt++;
  self->data[idx] = *pdt;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_put_u32(olsr_pktbuf_t *self, size_t idx, const olsr_u32_t dt)
{
  olsr_u32_t ndt = htonl(dt);
  olsr_u8_t *pdt = (olsr_u8_t *) & ndt;

  while (self->len + sizeof(olsr_u32_t) > self->capa)
    olsr_pktbuf_grow_capa(self);
  self->data[idx++] = *pdt++;
  self->data[idx++] = *pdt++;
  self->data[idx++] = *pdt++;
  self->data[idx] = *pdt;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_put_byte_ary(olsr_pktbuf_t *self, size_t idx,
    const olsr_u8_t * dt, const size_t sz)
{
  while (self->len + sz > self->capa)
    olsr_pktbuf_grow_capa(self);
  memcpy(&self->data[idx], dt, sz);
  self->len += sz;
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_put_ip(struct olsrv2* olsr, olsr_pktbuf_t *self, size_t idx,
    const union olsr_ip_addr *ip)
{
    struct olsrd_config* olsr_cnf = ((struct olsrv2*)olsr)->olsr_cnf;
  return olsr_pktbuf_put_byte_ary(self, idx, (const olsr_u8_t *)ip, IP_LEN);
}

/**** get ****/

size_t
olsr_pktbuf_get_index(olsr_pktbuf_t *self)
{
    return self->p - self->data;
}

olsr_bool
olsr_pktbuf_get_u16(olsr_pktbuf_t *self, olsr_u16_t * r)
{
  if (sizeof(olsr_u16_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = htons(*(olsr_u16_t *) (self->p));
  self->p += sizeof(olsr_u16_t);
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_get_u32(olsr_pktbuf_t *self, olsr_u32_t * r)
{
  if (sizeof(olsr_u32_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = htonl(*(olsr_u32_t *) (self->p));
  self->p += sizeof(olsr_u32_t);
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_get_byte_ary(olsr_pktbuf_t *self, olsr_u8_t * r, size_t len)
{
  if (olsr_pktbuf_remain(self) < len)
    return OLSR_FALSE;
  memcpy(r, self->p, len);
  self->p += len;
  return OLSR_TRUE;
}


olsr_bool
olsr_pktbuf_get_ip(struct olsrv2* olsr, olsr_pktbuf_t *self, union olsr_ip_addr *r)
{
    struct olsrd_config* olsr_cnf = ((struct olsrv2*)olsr)->olsr_cnf;
  return olsr_pktbuf_get_byte_ary(self, (olsr_u8_t *) r, IP_LEN);
}

/**** peek ****/

olsr_bool
olsr_pktbuf_peek_u8(olsr_pktbuf_t *self, olsr_u8_t * r)
{
  if (sizeof(olsr_u8_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = *(olsr_u8_t *) (self->p);
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_peek_u16(olsr_pktbuf_t *self, olsr_u16_t * r)
{
  if (sizeof(olsr_u16_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = htons(*(olsr_u16_t *) (self->p));
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_peek_u32(olsr_pktbuf_t *self, olsr_u32_t * r)
{
  if (sizeof(olsr_u32_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = htonl(*(olsr_u32_t *) (self->p));
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_peek_byte_ary(olsr_pktbuf_t *self, olsr_u8_t * r, size_t len)
{
  if (olsr_pktbuf_remain(self) < len)
    return OLSR_FALSE;
  memcpy(r, self->p, len);
  return OLSR_TRUE;
}

olsr_bool
olsr_pktbuf_peek_ip(struct olsrv2* olsr, olsr_pktbuf_t *self, union olsr_ip_addr *r)
{
    struct olsrd_config* olsr_cnf = ((struct olsrv2*)olsr)->olsr_cnf;
  return olsr_pktbuf_peek_byte_ary(self, (olsr_u8_t *) r, IP_LEN);
}
}
