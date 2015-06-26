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

#ifndef __MPOLSR_BUF_H__
#define __MPOLSR_BUF_H__
#include "mp_olsr_types.h"
#include <stdio.h>

//WIN FIX: Changed code to use olsr types in this file
//#include <stdint.h>

namespace MPOLSRv2{


typedef struct olsr_pktbuf
{
  size_t capa;          // >0:capacity / ==0:child buffer
  size_t len;
  olsr_u8_t *p;
  olsr_u8_t *data;
} olsr_pktbuf_t;


/**** inline functions ****/

/**
 *
 */
static //inline
void
olsr_pktbuf_clear(olsr_pktbuf_t *self)
{
  self->len = 0;
  self->p = self->data;
}

/**
 *
 */
static //inline
void
olsr_pktbuf_clear_ptr(olsr_pktbuf_t *self)
{
  self->p = 0;
}

/**
 *
 */
/*
static inline void
olsr_pktbuf_skip_to_next_32bit_align(olsr_pktbuf_t *self)
{
  uint32_t p = *(uint32_t *)self->p;
  if (p % 4 != 0)
    self->p += 4 - (p % 4); // padding
}
*/
/**
 *
 */
static //inline
size_t
olsr_pktbuf_remain(olsr_pktbuf_t *self)
{
  return self->len - (self->p - self->data + 1);
}

/****/

#ifdef __cplusplus
//extern "C"{
#endif


olsr_pktbuf_t *olsr_pktbuf_alloc(void);
olsr_pktbuf_t *olsr_pktbuf_alloc_with_capa(const size_t capa);
olsr_pktbuf_t *olsr_pktbuf_alloc_child(olsr_pktbuf_t *, size_t len);
void olsr_pktbuf_grow_capa(olsr_pktbuf_t *);

void olsr_pktbuf_free(olsr_pktbuf_t **);

#ifdef __cplusplus
//}
#endif


/*
 * Append data at the tail of buffer
 */

static //inline
olsr_bool
olsr_pktbuf_append_u8(olsr_pktbuf_t *self, const olsr_u8_t dt)
{
  while (self->len + 1 > self->capa)
    olsr_pktbuf_grow_capa(self);
  self->data[self->len++] = dt;
  return OLSR_TRUE;
}

olsr_bool olsr_pktbuf_append_u16(olsr_pktbuf_t *, const olsr_u16_t);
olsr_bool olsr_pktbuf_append_u32(olsr_pktbuf_t *, const olsr_u32_t);
olsr_bool olsr_pktbuf_append_byte_ary(olsr_pktbuf_t *, const olsr_u8_t *, size_t);
olsr_bool olsr_pktbuf_append_ip(struct olsrv2* olsr, olsr_pktbuf_t *, const union olsr_ip_addr *);
olsr_bool olsr_pktbuf_append_pktbuf(olsr_pktbuf_t *, const olsr_pktbuf_t *);

/*
 * Write data at the index
 */
olsr_bool olsr_pktbuf_put_u8(olsr_pktbuf_t *, size_t idx, const olsr_u8_t);
olsr_bool olsr_pktbuf_put_u16(olsr_pktbuf_t *, size_t idx, const olsr_u16_t);
olsr_bool olsr_pktbuf_put_u32(olsr_pktbuf_t *, size_t idx, const olsr_u32_t);
olsr_bool olsr_pktbuf_put_byte_ary(olsr_pktbuf_t *, size_t idx,
                   const olsr_u8_t *, size_t);
olsr_bool olsr_pktbuf_put_ip(struct olsrv2* olsr, olsr_pktbuf_t *, size_t idx,
    const union olsr_ip_addr *);

/*
 * Read data and increment pointer
 */
static //inline
olsr_bool
olsr_pktbuf_get_u8(olsr_pktbuf_t *self, olsr_u8_t * r)
{
  if (sizeof(olsr_u8_t) > olsr_pktbuf_remain(self))
    return OLSR_FALSE;
  *r = *(olsr_u8_t *) (self->p);
  self->p += sizeof(olsr_u8_t);
  return OLSR_TRUE;
}

size_t olsr_pktbuf_get_index(olsr_pktbuf_t*);

olsr_bool olsr_pktbuf_get_u16(olsr_pktbuf_t *, olsr_u16_t *);
olsr_bool olsr_pktbuf_get_u32(olsr_pktbuf_t *, olsr_u32_t *);
olsr_bool olsr_pktbuf_get_byte_ary(olsr_pktbuf_t *, olsr_u8_t *, size_t);
olsr_bool olsr_pktbuf_get_ip(struct olsrv2* olsr, olsr_pktbuf_t *, union olsr_ip_addr *);

/*
 * Read data but does not increment pointer
 */
olsr_bool olsr_pktbuf_peek_u8(olsr_pktbuf_t *, olsr_u8_t *);
olsr_bool olsr_pktbuf_peek_u16(olsr_pktbuf_t *, olsr_u16_t *);
olsr_bool olsr_pktbuf_peek_u32(olsr_pktbuf_t *, olsr_u32_t *);
olsr_bool olsr_pktbuf_peek_byte_ary(olsr_pktbuf_t *, olsr_u8_t *, size_t);
olsr_bool olsr_pktbuf_peek_ip(struct olsrv2* olsr, olsr_pktbuf_t *, union olsr_ip_addr *);
}
#endif /* __OLSR_BUF_H__ */
