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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mp_olsr_debug.h"

//WIN FIX
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_address_compress.h"
#include "mp_tlv_compress.h"

#include "mp_pktbuf.h"
#include "mp_olsr_conf.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

static void create_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                   OLSR_LIST *block,
                   olsr_u8_t tlv_type,
                   olsr_u8_t tlv_value);
static void create_other_neigh_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *);
static void create_linkstatus_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *);
// static void create_R_etx_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *); //codexxx
static void create_mpr_selection_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *);
static void create_other_if_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *);
static void create_prefix_tlv_by_list(void *, OLSR_LIST *, OLSR_LIST *);

/* static function prototypes */
static void build_tlv_msg(olsr_pktbuf_t *, OLSR_LIST *);


static void create_tlv_for_index_hello(olsr_pktbuf_t *,
    BASE_ADDRESS *, olsr_u32_t, olsr_u8_t, olsr_u8_t);

static void create_simple_tlv(olsr_pktbuf_t *,
                  const olsr_u8_t type,
                  const olsr_u8_t semantics,
                  const olsr_u8_t length,
                  const olsr_u8_t index_start,
                  const olsr_u8_t index_stop,
                  const olsr_u8_t *value);

static void free_tlv_block(OLSR_LIST *);

#ifdef USE_MULTI_VALUE
void
create_hello_addr_tlv_by_multivalue(void *olsr, OLSR_LIST *tlv_block,
                    OLSR_LIST *block,
                    olsr_u8_t tlv_type);
#endif


/* function implimentations */

/**
 * <tlv-block>
 * = <tlv-length> <tlv>*
 * <tlv>
 * = <type> <tlv-semantics> <length>? <index-start>? <index-stop>? <value>?
 */
static void
build_tlv_msg(olsr_pktbuf_t *pktbuf, OLSR_LIST *tlv_block)
{
//Static Fix
  //static olsr_pktbuf_t *tlv_buf = NULL;
  olsr_pktbuf_t *tlv_buf = NULL;
  OLSR_LIST_ENTRY *p = NULL;

  olsr_u16_t extend_length;
	//wiss: initialisation du buffer temporaire qu'on va s'en servir
  tlv_buf = olsr_pktbuf_alloc_with_capa(64);
  olsr_pktbuf_clear(tlv_buf);

  for (p = tlv_block->head; p != NULL; p = p->next)
    {
      BASE_TLV *const tlv = (BASE_TLV *)p->data;
      olsr_pktbuf_append_u8(tlv_buf, tlv->tlv_type);
      olsr_pktbuf_append_u8(tlv_buf, tlv->tlv_semantics);

      //index start and stop
      if((tlv->tlv_semantics & NO_INDEX) == 0)
    { //wiss: hon bifout kell chi ella el NO_INDEX
      olsr_pktbuf_append_u8(tlv_buf, tlv->index_start);
      if((tlv->tlv_semantics & SINGLE_INDEX) == 0)// wiss: hon bifout kell chi ella el single index
        olsr_pktbuf_append_u8(tlv_buf, tlv->index_stop); // wiss: hon byetaba2 kell chi ella el no index wel single index ya3ni el tabi3i
    }

      //no value bit  unset
      if((tlv->tlv_semantics & NO_VALUE) == 0)
    { // wiss: hon bifout kell chi ella NO_VALUE ya3ni bifout kell chi bass akid mech MPRSELECTOR
      //extended bit
      if((tlv->tlv_semantics & EXTENDED) == 0)  // wiss: chou extended ma fhemet ma mar2et wala marra !!
        olsr_pktbuf_append_u8(tlv_buf, tlv->tlv_length);
      else
        {
          extend_length = tlv->tlv_length;
          olsr_pktbuf_append_u16(tlv_buf, htons(extend_length));
        }
    }
      // value
      if((tlv->tlv_semantics & NO_VALUE) == 0)
    olsr_pktbuf_append_byte_ary(tlv_buf, tlv->value, tlv->tlv_length);
      //multi value bit unsupported
    }
  olsr_pktbuf_append_u16(pktbuf, (olsr_u16_t)tlv_buf->len);
  olsr_pktbuf_append_pktbuf(pktbuf, tlv_buf);

  //XXX:debug_code(print_tlv_msg(msg_head));
  olsr_pktbuf_free(&tlv_buf);

  //free(tlv_buf->data);
  //free(tlv_buf);
}

/*
 * Create <tlv-block>
 */
void
build_tlv_local_by_list(void *olsr, olsr_pktbuf_t *buf, OLSR_LIST *addr_list) {
  OLSR_LIST tlv_block;
  OLSR_InitList(&tlv_block);

  create_other_if_tlv_by_list(olsr, &tlv_block, addr_list);
  build_tlv_msg(buf, &tlv_block);

  free_tlv_block(&tlv_block);
}

void
build_tlv_hello_by_list(void *olsr, olsr_pktbuf_t *buf, OLSR_LIST *addr_list)
{
  OLSR_LIST tlv_block;
  OLSR_InitList(&tlv_block);


#ifdef USE_MULTI_VALUE
  create_hello_addr_tlv_by_multivalue(olsr, &tlv_block,
                      addr_list,
                      Link_Status);

  create_hello_addr_tlv_by_multivalue(olsr, &tlv_block,
                      addr_list,
                      PREFIX_LENGTH);
#else

  /*   create_tlv_by_list(&tlv_block, addr_list, Link_Status, SYMMETRIC); */
  /*   create_tlv_by_list(&tlv_block, addr_list, Link_Status, ASYMMETRIC); */
  /*     create_tlv_by_list(&tlv_block, addr_list, Link_Status, HEARD); */
  /* create_tlv_by_list(&tlv_block, addr_list, Link_Status, LOST); */
  create_linkstatus_tlv_by_list(olsr, &tlv_block, addr_list);
  //create_R_etx_tlv_by_list(olsr, &tlv_block, addr_list);
  create_mpr_selection_tlv_by_list(olsr, &tlv_block, addr_list); 
  create_other_neigh_tlv_by_list(olsr, &tlv_block, addr_list);
  create_prefix_tlv_by_list(olsr, &tlv_block, addr_list);
// wiss byetkawan 3enna list "tlv_block" b2alba bel partie data link status w mpr selection w .... TLVS 
//wiss : hella2 ma ba2 3layna ella nelze2on bel buffer
#endif

/*   create_tlv_by_list(&tlv_block, addr_list, Other_If, OLSR_TRUE); */
/*   create_tlv_by_list(&tlv_block, addr_list, MPR_Selection, OLSR_TRUE); */

  build_tlv_msg(buf, &tlv_block);

  free_tlv_block(&tlv_block);
}




/*
 * Create <tlv-block> for ...
 * XXX add 'OLD_TC_TLV', 'PREFIX_LENGTH_TLV' ?
 */
void
build_tlv_block_tc(olsr_pktbuf_t *buf)
{
  olsr_pktbuf_append_u16(buf, 0);
}


#ifdef USE_MULTI_VALUE
//create multivalue tlv
void
create_hello_addr_tlv_by_multivalue(void *olsr, OLSR_LIST *tlv_block,
                    OLSR_LIST *block,
                    olsr_u8_t tlv_type)
{
  BASE_TLV base_tlv;
  OLSR_LIST_ENTRY *entry;
  BLOCK_DATA *data, *next_data;

  olsr_u8_t index_start, index_stop;
  olsr_u32_t index, tlv_length;
  olsr_bool set_index_start;
//Static Fix
  //static olsr_pktbuf_t *buf = NULL;
  olsr_pktbuf_t *buf = NULL;

  index_start = index_stop = index =0;

  tlv_length = 0;
  set_index_start = OLSR_FALSE;

  buf = olsr_pktbuf_alloc_with_capa(255 * sizeof(olsr_u8_t));
  olsr_pktbuf_clear(buf);

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data;
    switch(tlv_type){
    case Link_Status:
      {
    if(data->link_status != 255){

      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
        index_start = index;
        set_index_start = OLSR_TRUE;
      }

      index_stop = index;
      tlv_length += sizeof(olsr_u8_t);
      olsr_pktbuf_append_u8(buf, data->link_status);

      //last addr
      if(index == block->numEntry -1){
        base_tlv.tlv_type = tlv_type;
        base_tlv.tlv_semantics = MULTI_VALUE;
        base_tlv.tlv_length = tlv_length;
        base_tlv.index_start = index_start;
        base_tlv.index_stop = index_stop;

        //check semantics
        if(index_start == 0){
          base_tlv.tlv_semantics |= NO_INDEX;
        }else if(index_start == index_stop){
          base_tlv.tlv_semantics |= SINGLE_INDEX;
        }

        //set value
        base_tlv.value = (olsr_u8_t *)olsr_malloc(tlv_length, __FUNCTION__);
        memcpy(base_tlv.value, buf->data, tlv_length);

        //insert list
        OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
        set_index_start = OLSR_FALSE;
        olsr_pktbuf_clear(buf);
        tlv_length =0;

      }else if (index < block->numEntry -1){
        next_data = (BLOCK_DATA *)entry->next->data;
        if(next_data->link_status == 255){
          base_tlv.tlv_type = tlv_type;
          base_tlv.tlv_semantics = MULTI_VALUE;
          base_tlv.tlv_length = tlv_length;
          base_tlv.index_start = index_start;
          base_tlv.index_stop = index_stop;

          //check semantics
          if(index_start == index_stop){
        base_tlv.tlv_semantics |= SINGLE_INDEX;
          }

          //set value
          base_tlv.value = (olsr_u8_t *)olsr_malloc(tlv_length, __FUNCTION__);
          memcpy(base_tlv.value, buf->data, tlv_length);

          //insert list
          OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
          set_index_start = OLSR_FALSE;
          olsr_pktbuf_clear(buf);
          tlv_length = 0;
        }
      }//if else if
    }//link_status != 255
      }//case
      break;

    case PREFIX_LENGTH:
      {
    if(data->Prefix_Length != 255){

      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
        index_start = index;
        set_index_start = OLSR_TRUE;
      }

      index_stop = index;
      tlv_length += sizeof(olsr_u8_t);
      olsr_pktbuf_append_u8(buf, data->Prefix_Length);

      //last addr
      if(index == block->numEntry -1){
        base_tlv.tlv_type = tlv_type;
        base_tlv.tlv_semantics = MULTI_VALUE;
        base_tlv.tlv_length = tlv_length;
        base_tlv.index_start = index_start;
        base_tlv.index_stop = index_stop;

        //check semantics
        if(index_start == 0){
          base_tlv.tlv_semantics |= NO_INDEX;
        }else if(index_start == index_stop){
          base_tlv.tlv_semantics |= SINGLE_INDEX;
        }

        //set value
        base_tlv.value = (olsr_u8_t *)olsr_malloc(tlv_length, __FUNCTION__);
        memcpy(base_tlv.value, buf->data, tlv_length);

        //insert list
        OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
        set_index_start = OLSR_FALSE;
        olsr_pktbuf_clear(buf);
        tlv_length =0;

      }else if (index < block->numEntry -1){
        next_data = (BLOCK_DATA *)entry->next->data;
        if(next_data->Prefix_Length == 255){
          base_tlv.tlv_type = tlv_type;
          base_tlv.tlv_semantics = MULTI_VALUE;
          base_tlv.tlv_length = tlv_length;
          base_tlv.index_start = index_start;
          base_tlv.index_stop = index_stop;

          //check semantics
          if(index_start == index_stop){
        base_tlv.tlv_semantics |= SINGLE_INDEX;
          }

          //set value
          base_tlv.value = (olsr_u8_t *)olsr_malloc(tlv_length, __FUNCTION__);
          memcpy(base_tlv.value, buf->data, tlv_length);

          //insert list
          OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
          set_index_start = OLSR_FALSE;
          olsr_pktbuf_clear(buf);
          tlv_length = 0;
        }
      }//if else if
    }//Prefix_LENGTH != 255
      }//case
      break;

    default:
      olsr_error("%s\n", __FUNCTION__);

    }//switch

    index++;
    entry = entry->next;
  }
  olsr_pktbuf_free(&buf);

  //free(buf->data);
  //free(buf);
}

#endif

static void create_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                   OLSR_LIST *block,
                   olsr_u8_t tlv_type,
                   olsr_u8_t tlv_value)
{
  BASE_TLV base_tlv;

  OLSR_LIST_ENTRY *tmp = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;

  olsr_u8_t index_start, index_stop;
  olsr_u32_t index = 0;
  olsr_bool flag_A;

  index_start = index_stop = 0;
  flag_A = OLSR_FALSE;

  tmp = block->head;
  while (tmp)
    {
      data = (BLOCK_DATA *)tmp->data;

      switch (tlv_type)
    {
    case Link_Status:
      {
        if (data->link_status == tlv_value)
          {
        if (!flag_A)
          {
            index_start = (olsr_u8_t)index;
            flag_A = OLSR_TRUE;
          }
        index_stop = (olsr_u8_t)index;

        if (flag_A)
          {
            if (index == block->numEntry - 1)
              {
            base_tlv.tlv_type = tlv_type;
            base_tlv.tlv_semantics = ALL_ZERO;
            base_tlv.tlv_length = sizeof(olsr_u8_t);
            base_tlv.index_start = index_start;
            base_tlv.index_stop = index_stop;
            base_tlv.value =
              (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
            memcpy(base_tlv.value, &tlv_value,
                   base_tlv.tlv_length);

            if(index_start == 0)
              base_tlv.tlv_semantics |= NO_INDEX;
            else if(index_start == index_stop)
              base_tlv.tlv_semantics |= SINGLE_INDEX;

            OLSR_InsertList( tlv_block, &base_tlv,
                    sizeof(BASE_TLV));

            flag_A = OLSR_FALSE;
              }
            else if (index < block->numEntry - 1)
              {
            next_data = (BLOCK_DATA *)tmp->next->data;

            if (next_data->link_status != tlv_value)
              {
                base_tlv.tlv_type = tlv_type;
                base_tlv.tlv_semantics = ALL_ZERO;
                base_tlv.tlv_length = sizeof(olsr_u8_t);
                base_tlv.index_start = index_start;
                base_tlv.index_stop = index_stop;
                base_tlv.value =
                  (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
                memcpy(base_tlv.value, &tlv_value,
                   base_tlv.tlv_length);

                if(index_start == index_stop)
                  base_tlv.tlv_semantics |= SINGLE_INDEX;

                OLSR_InsertList( tlv_block, &base_tlv,
                    sizeof(BASE_TLV));

                flag_A = OLSR_FALSE;
              }
              }
          }
          }
        break;
      }

    case Other_If:
      {
        if (data->other_if == tlv_value)
          {
        if (!flag_A)
          {
            index_start = (olsr_u8_t)index;
            flag_A = OLSR_TRUE;
          }
        index_stop = (olsr_u8_t)index;

        if (flag_A)
          {
            if (index == block->numEntry - 1)
              {
            base_tlv.tlv_type = tlv_type;

            base_tlv.tlv_semantics = NO_VALUE;
            base_tlv.tlv_length = 0;

            base_tlv.index_start = index_start;
            base_tlv.index_stop = index_stop;

            base_tlv.value = NULL;

            if(index_start == index_stop)
              base_tlv.tlv_semantics |= SINGLE_INDEX;
            else if(index_start == 0)
              base_tlv.tlv_semantics |= NO_INDEX;

            OLSR_InsertList( tlv_block, &base_tlv,
                    sizeof(BASE_TLV));

            flag_A = OLSR_FALSE;
              }
            else if (index < block->numEntry - 1)
              {
            next_data = (BLOCK_DATA *)tmp->next->data;

            if (next_data->other_if != tlv_value)
              {
                base_tlv.tlv_type = tlv_type;

                base_tlv.tlv_semantics = NO_VALUE;
                base_tlv.tlv_length = 0;

                base_tlv.index_start = index_start;
                base_tlv.index_stop = index_stop;

                base_tlv.value = NULL;

                if(index_start == index_stop)
                  base_tlv.tlv_semantics |= SINGLE_INDEX;

                OLSR_InsertList( tlv_block, &base_tlv,
                        sizeof(BASE_TLV));

                flag_A = OLSR_FALSE;
              }
              }
          }
          }
        break;
      }

    case MPR_Selection:
      {
        if (data->MPR_Selection == tlv_value)
          {
        if (!flag_A)
          {
            index_start = (olsr_u8_t)index;
            flag_A = OLSR_TRUE;
          }
        index_stop = (olsr_u8_t)index;

        if (flag_A)
          {
            if (index == block->numEntry - 1)
              {
            base_tlv.tlv_type = tlv_type;

            base_tlv.tlv_semantics = NO_VALUE;
            base_tlv.tlv_length = 0;

            base_tlv.index_start = index_start;
            base_tlv.index_stop = index_stop;

            base_tlv.value = NULL;

            if(index_start == index_stop)
              base_tlv.tlv_semantics |= SINGLE_INDEX;
            else if(index_start == 0)
              base_tlv.tlv_semantics |= NO_INDEX;

            OLSR_InsertList( tlv_block, &base_tlv,
                sizeof(BASE_TLV));

            flag_A = OLSR_FALSE;
              }
            else if (index < block->numEntry - 1)
              {
            next_data = (BLOCK_DATA *)tmp->next->data;

            if (next_data->MPR_Selection != tlv_value)
              {
                base_tlv.tlv_type = tlv_type;

                base_tlv.tlv_semantics = NO_VALUE;
                base_tlv.tlv_length = 0;

                base_tlv.index_start = index_start;
                base_tlv.index_stop = index_stop;

                base_tlv.value = NULL;

                if(index_start == index_stop)
                  base_tlv.tlv_semantics |= SINGLE_INDEX;

                OLSR_InsertList( tlv_block, &base_tlv,
                        sizeof(BASE_TLV));

                flag_A = OLSR_FALSE;
              }
              }
          }
          }
        break;
      }
    case PREFIX_LENGTH:
      {
        if (data->Prefix_Length == tlv_value)
          {
        if (!flag_A)
          {
            index_start = (olsr_u8_t)index;
            flag_A = OLSR_TRUE;
          }
        index_stop = (olsr_u8_t)index;

        if (flag_A)
          {
            if (index == block->numEntry - 1)
              {
            base_tlv.tlv_type = tlv_type;
            base_tlv.tlv_semantics = ALL_ZERO;
            base_tlv.tlv_length = sizeof(olsr_u8_t);
            base_tlv.index_start = index_start;
            base_tlv.index_stop = index_stop;
            base_tlv.value =
              (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
            memcpy(base_tlv.value, &tlv_value,
                   base_tlv.tlv_length);
            if(index_start == index_stop)
              base_tlv.tlv_semantics |= SINGLE_INDEX;
            else if(index_start == 0)
              base_tlv.tlv_semantics |= NO_INDEX;

            OLSR_InsertList( tlv_block, &base_tlv,
                    sizeof(BASE_TLV));

            flag_A = OLSR_FALSE;
              }
            else if (index < block->numEntry - 1)
              {
            next_data = (BLOCK_DATA *)tmp->next->data;

            if (next_data->Prefix_Length != tlv_value)
              {
                base_tlv.tlv_type = tlv_type;
                base_tlv.tlv_semantics = ALL_ZERO;
                base_tlv.tlv_length = sizeof(olsr_u8_t);
                base_tlv.index_start = index_start;
                base_tlv.index_stop = index_stop;
                base_tlv.value =
                  (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
                memcpy(base_tlv.value, &tlv_value,
                   base_tlv.tlv_length);
                if(index_start == index_stop)
                  base_tlv.tlv_semantics |= SINGLE_INDEX;


                OLSR_InsertList( tlv_block, &base_tlv,
                        sizeof(BASE_TLV));

                flag_A = OLSR_FALSE;
              }
              }
          }
          }
        break;
      }


    default:
      olsr_error("%s\n", __FUNCTION__);
    }

      index++;
      tmp = tmp->next;
    }
}

static void create_other_neigh_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                       OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = tlv_value = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data;

    if(data->other_neigh != 255){
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
    tlv_value = data->other_neigh;
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){
    //set semantics
    if(index_start == 0)
      semantics = NO_INDEX;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX;

      }else{  // case index < block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->other_neigh == 255 || next_data->other_neigh != tlv_value){
      //set semantics
      if(index_start == index_stop)
        semantics = SINGLE_INDEX;
    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//if (index ==..)  else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = Other_Neigh;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = sizeof(olsr_u8_t);
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
      memcpy(base_tlv.value, &tlv_value, base_tlv.tlv_length);

      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while

}

static void create_linkstatus_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                      OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = tlv_value = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data; // wiss: kell el ma3loumet ip w link status...covered  w hel esas

    if(data->link_status != 255){ // wiss: 255 hiye el valeur maximal bass ma ba3ref chou bye2sod fiya betsawar hayda jar mech jar el jar
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){ //A wiss: bi fout hon bass awal marra!!
    tlv_value = data->link_status;
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }//A
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){ 
    //set semantics  // wiss: wasal 3al niheye
    if(index_start == 0)
      semantics = NO_INDEX;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX;

      }else{  //B  case index <   block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->link_status == 255 || next_data->link_status != tlv_value){
      //set semantics // wiss: betsawar hayda jar el jar aw tghayar el link status ben entry weli ba3da
      if(index_start == index_stop)
        semantics = SINGLE_INDEX;
    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//B if (index ==..) & else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = Link_Status;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = sizeof(olsr_u8_t);
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
      memcpy(base_tlv.value, &tlv_value, base_tlv.tlv_length);

      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while
    // wiss: hon bel niheye betkoun tkawanet 3enna list bel data 3enna ma3loumet 3an el TLV taba3 kell addresset yalli bel list "block"
  // wiss: w iza el adresset yalli wara ba3don 3endon kellon LINK_STATUS nafs el chi men7ot index start w index end
  //wiss: wel semantics bi 3aber 3an 3adad el @ yalli metel ba3don wara ba3don...

}
/*
//codexxx
static void create_R_etx_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                      OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value,linkcost= 1;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = tlv_value = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data; // wiss: kell el ma3loumet ip w link status...covered  w hel esas

    if(data->link_status = SYMMETRIC){ // wiss: 255 hiye el valeur maximal bass ma ba3ref chou bye2sod fiya
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){ //A wiss: bi fout hon bass awal marra!!
    tlv_value = 1; // ca doit etre changee pour etre linkcost
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }//A
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){ 
    //set semantics  // wiss: wasal 3al niheye
    if(index_start == 0)
      semantics = NO_INDEX;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX;

      }else{  //B  case index <   block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->link_status != SYMMETRIC|| next_data->link_status != data->link_status){
      //set semantics
      if(index_start == index_stop)
        semantics = SINGLE_INDEX;
    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//B if (index ==..) & else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = R_etx ;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = sizeof(olsr_u8_t);
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
      memcpy(base_tlv.value, &linkcost, base_tlv.tlv_length);
      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while
    // wiss: hon bel niheye betkoun tkawanet 3enna list bel data 3enna ma3loumet 3an el TLV taba3 kell addresset yalli bel list "block"
  // wiss: w iza el adresset yalli wara ba3don 3endon kellon LINK_STATUS nafs el chi men7ot index start w index end
  //wiss: wel semantics bi 3aber 3an 3adad el @ yalli metel ba3don wara ba3don...

}

// end codexxx
*/
static void create_mpr_selection_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                         OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data;

    if(data->MPR_Selection == OLSR_TRUE){
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
    tlv_value = data->MPR_Selection;
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){
    //set semantics
    if(index_start == 0)
      semantics = NO_INDEX | NO_VALUE;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX | NO_VALUE;
    else
      semantics = NO_VALUE;

      }else{  // case index < block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->MPR_Selection != OLSR_TRUE){
      //set semantics
      if(index_start == index_stop)
        semantics = SINGLE_INDEX | NO_VALUE;
      else
        semantics = NO_VALUE;

    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//if (index ==..)  else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = MPR_Selection;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = 0;
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = NULL;

      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while

}

static void create_other_if_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                    OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data;

    if(data->other_if == OLSR_TRUE){
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
    tlv_value = data->other_if;
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){
    //set semantics
    if(index_start == 0)
      semantics = NO_INDEX | NO_VALUE;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX | NO_VALUE;
    else
      semantics = NO_VALUE;

      }else{  // case index < block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->other_if != OLSR_TRUE){
      //set semantics
      if(index_start == index_stop)
        semantics = SINGLE_INDEX | NO_VALUE;
      else
        semantics = NO_VALUE;

    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//if (index ==..)  else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = Other_If;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = 0;
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = NULL;

      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while

}

static void create_prefix_tlv_by_list(void *olsr, OLSR_LIST *tlv_block,
                      OLSR_LIST *block){
  OLSR_LIST_ENTRY *entry = NULL;
  BLOCK_DATA *data = NULL, *next_data = NULL;
  BASE_TLV base_tlv;

  olsr_u8_t semantics, index_start, index_stop, tlv_value;
  olsr_u32_t index = 0;
  olsr_bool set_index_start;

  index_start = index_stop = semantics = tlv_value = 0;
  set_index_start = OLSR_FALSE;

  entry = block->head;
  while(entry){
    data = (BLOCK_DATA *)entry->data;

    if(data->Prefix_Length != 255){
      //check index_start set or not
      if(set_index_start == OLSR_FALSE){
    tlv_value = data->Prefix_Length;
    index_start = (olsr_u8_t)index;
    set_index_start = OLSR_TRUE;
      }
      index_stop = (olsr_u8_t)index;

      if(index == block->numEntry -1){
    //set semantics
    if(index_start == 0)
      semantics = NO_INDEX;
    else if(index_start == index_stop)
      semantics = SINGLE_INDEX;

      }else{  // case index < block->numEntry -1
    next_data = (BLOCK_DATA *)entry->next->data;
    if(next_data->Prefix_Length == 255 || next_data->link_status != tlv_value){
      //set semantics
      if(index_start == index_stop)
        semantics = SINGLE_INDEX;

    }else{  //next entry
      index++;
      entry = entry->next;
      continue;
    }
      }//if (index ==..)  else if(...) & else not reachable

      //set all val
      base_tlv.tlv_type = PREFIX_LENGTH;
      base_tlv.tlv_semantics = semantics;
      base_tlv.tlv_length = sizeof(olsr_u8_t);
      base_tlv.index_start = index_start;
      base_tlv.index_stop = index_stop;
      base_tlv.value = (olsr_u8_t *)olsr_malloc(base_tlv.tlv_length, __FUNCTION__);
      memcpy(base_tlv.value, &tlv_value, base_tlv.tlv_length);

      //inset base_tlv
      OLSR_InsertList( tlv_block, &base_tlv, sizeof(BASE_TLV));
      set_index_start  = OLSR_FALSE;
      semantics = 0;
    }
    index++;
    entry = entry->next;
  }//while

}

void
build_tlv_attached_network_by_list(void *olsr, olsr_pktbuf_t *buf, OLSR_LIST *addr_list)
{
  OLSR_LIST tlv_block;
  OLSR_InitList(&tlv_block);

  OLSR_LIST_ENTRY* tmp = NULL, *tmp1 = NULL, * next = NULL;
  BLOCK_DATA* data = NULL, *tmpData = NULL;

  tmp = addr_list->head;

  while(tmp)
    {
      data = (BLOCK_DATA* )tmp->data;
      create_tlv_by_list(olsr, &tlv_block,
             addr_list,
             PREFIX_LENGTH,
             data->Prefix_Length);

      tmp1 = tmp->next;
      while(tmp1){
        tmpData = (BLOCK_DATA* )tmp1->data;
        next = tmp1->next;
        if(data->Prefix_Length == tmpData->Prefix_Length){
           OLSR_DeleteListEntry(addr_list, tmp1);
        }
        tmp1 = next;
      }

      //delete current entry also
      tmp1 = tmp->next;
      OLSR_DeleteListEntry(addr_list, tmp);
      tmp = tmp1;
    }

  build_tlv_msg(buf, &tlv_block);
  free_tlv_block(&tlv_block);
}


/*
 * Create <tlv-block> for ...
 * XXX no TLV
 */
void
build_tlv_block_local(olsr_pktbuf_t *buf)
{
  olsr_pktbuf_append_u16(buf, 0);
  //debug_code(print_tlv_msg(msg));
}


void
build_tlv_block_for_index_attached_network(olsr_pktbuf_t *buf,
                 BASE_ADDRESS *base,
                 olsr_u32_t index)
{
//Static Fix
  //static olsr_pktbuf_t *tlv_buf = NULL;
  olsr_pktbuf_t *tlv_buf = NULL;

  tlv_buf = olsr_pktbuf_alloc_with_capa(64);
  olsr_pktbuf_clear(tlv_buf);

  create_simple_tlv(tlv_buf,
            PREFIX_LENGTH,
            SINGLE_INDEX,
            1,
            0,
            0,
            &base->data[index].Prefix_Length);

  // <tlv-block>
  olsr_pktbuf_append_u16(buf, (olsr_u16_t)tlv_buf->len);    // <tlv-length>
  olsr_pktbuf_append_pktbuf(buf, tlv_buf);  // <tlv

  olsr_pktbuf_free(&tlv_buf);

  //free(tlv_buf->data);
  //free(tlv_buf);
}


/*
 * Create <tlv-block> for ...
 * XXX
 */
void build_tlv_block_for_index_local(olsr_pktbuf_t *buf, BASE_ADDRESS *base,
                     olsr_u32_t index) {
//Static Fix
  //static olsr_pktbuf_t *tlv_buf = NULL;
  olsr_pktbuf_t *tlv_buf = NULL;

  tlv_buf = olsr_pktbuf_alloc_with_capa(64);
  olsr_pktbuf_clear(tlv_buf);

  //Create TLV "Interface"
  create_tlv_for_index_hello(tlv_buf, base, index, Other_If, OLSR_TRUE);

  // <tlv-block>
  olsr_pktbuf_append_u16(buf, (olsr_u16_t)tlv_buf->len);    // <tlv-length>
  olsr_pktbuf_append_pktbuf(buf, tlv_buf);  // <tlv>*

  olsr_pktbuf_free(&tlv_buf);

  //free(tlv_buf->data);
  //free(tlv_buf);
}

void
build_tlv_block_for_index_hello(olsr_pktbuf_t *buf,
    BASE_ADDRESS *base, olsr_u32_t index)
{
//Static Fix
  //static olsr_pktbuf_t *tlv_buf = NULL;
  olsr_pktbuf_t *tlv_buf = NULL;

  tlv_buf = olsr_pktbuf_alloc_with_capa(64);
  olsr_pktbuf_clear(tlv_buf);

  //Create TLV "Link Status"
  create_tlv_for_index_hello(tlv_buf, base, index, Link_Status, SYMMETRIC);
  create_tlv_for_index_hello(tlv_buf, base, index, Link_Status, ASYMMETRIC);
  //  create_tlv_for_index_hello(tlv_buf, base, index, Link_Status, HEARD);
  create_tlv_for_index_hello(tlv_buf, base, index, Link_Status, LOST);

  //create TLV OtherNeigh
  create_tlv_for_index_hello(tlv_buf, base, index, Other_Neigh, SYMMETRIC);
  create_tlv_for_index_hello(tlv_buf, base, index, Other_Neigh, LOST);

  //Create TLV "MPR Selection"
  create_tlv_for_index_hello(tlv_buf, base, index, MPR_Selection, OLSR_TRUE);

  // <tlv-block>
  olsr_pktbuf_append_u16(buf, (olsr_u16_t)tlv_buf->len);    // <tlv-length>
  olsr_pktbuf_append_pktbuf(buf, tlv_buf);  // <tlv>*

  olsr_pktbuf_free(&tlv_buf);

  //free(tlv_buf->data);
  //free(tlv_buf);
}


/*
 * Create <tlv> for ...
 */
static void
create_tlv_for_index_hello(olsr_pktbuf_t *buf,
    BASE_ADDRESS *base,
    olsr_u32_t index, olsr_u8_t tlv_type, olsr_u8_t tlv_value)
{
  switch (tlv_type)
    {
    case Link_Status:
      if (base->data[index].link_status == tlv_value)
    create_simple_tlv(buf, tlv_type, SINGLE_INDEX, 1, 0, 0, &tlv_value);
      break;
    case Other_Neigh:
      if(base->data[index].other_neigh == tlv_value)
    create_simple_tlv(buf, tlv_type, SINGLE_INDEX, 1, 0, 0, &tlv_value);
      break;
    case Other_If:
      if (base->data[index].other_if== tlv_value)
    create_simple_tlv(buf, tlv_type, (SINGLE_INDEX | NO_VALUE), 1, 0, 0, &tlv_value);
      break;

    case MPR_Selection:
      if (base->data[index].MPR_Selection == tlv_value)
    create_simple_tlv(buf, tlv_type, (SINGLE_INDEX | NO_VALUE), 1, 0, 0, &tlv_value);
      break;


    default:
      olsr_error("%s\n", __FUNCTION__);
    }
}


void
free_tlv_block(OLSR_LIST *tlv_block)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  BASE_TLV *data_base_tlv = NULL;

  tmp = tlv_block->head;
  while (tmp)
    {
      data_base_tlv = (BASE_TLV *)tmp->data;
      if(data_base_tlv->value)
      free(data_base_tlv->value);

      tmp = tmp->next;
    }

  OLSR_DeleteList_Static(tlv_block);
}

void
print_tlv_block(OLSR_LIST *tlv_block)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  BASE_TLV *data_base_tlv = NULL;

  tmp = tlv_block->head;
  while (tmp)
    {
      data_base_tlv = (BASE_TLV *)tmp->data;

      olsr_printf("tlv_type = %d, tlv_length = %d, index_start = %d, index_stop = %d, ",
         data_base_tlv->tlv_type, data_base_tlv->tlv_length, data_base_tlv->index_start, data_base_tlv->index_stop);

      if(data_base_tlv->value)
    {
        olsr_printf("value = %d\n", *data_base_tlv->value);
    }

      tmp = tmp->next;
    }
}

void print_other_neigh_status(olsr_u8_t other_neigh){
  switch(other_neigh) {
  case SYMMETRIC:
    olsr_printf("SYMMETRIC ");
    break;
  case LOST:
    olsr_printf("LOST      ");
    break;
  default:
  {
  }
  //olsr_error("no such link status");
  }
}

void
print_link_status(olsr_u8_t link_status)
{
  switch (link_status)
    {
    case SYMMETRIC:
      {
    olsr_printf("SYMMETRIC ");
    break;
      }
    case ASYMMETRIC:
      {
    olsr_printf("ASYMMETRIC");
    break;
      }
      /*
    case HEARD:
      {
    olsr_printf("HEARD     ");
    break;
      }
      */
    case LOST:
      {
    olsr_printf("LOST      ");
    break;
      }
/*     case UNSPEC: */
/*       { */
/*  olsr_printf("UNSPEC"); */
/*  break; */
/*       } */
    default:
    {
    }
    //olsr_error("no such link status");
    }
}

void
print_interface(olsr_u8_t interfaceId)
{
  switch (interfaceId)
    {
    case OLSR_TRUE:
      {
    olsr_printf("YES");
    break;
      }
    case OLSR_FALSE:
      {
    olsr_printf("NO ");
    break;
      }
    default:
    {
    }
    //olsr_error("no such interface");
    }
}

void
print_mpr_selection(olsr_bool mpr_selection)
{
  switch (mpr_selection)
    {
    case OLSR_TRUE:
      {
    olsr_printf("TRUE ");
    break;
      }
    case OLSR_FALSE:
      {
    olsr_printf("FALSE");
    break;
      }
    default:
    {
    }
    //olsr_error("no such MPR Selection");
    }
}


/*
 * Create <tlv>
 */
static void
create_simple_tlv(olsr_pktbuf_t *buf,
          const olsr_u8_t type,
          const olsr_u8_t tlv_semantics,
          const olsr_u8_t length,
          const olsr_u8_t index_start,
          const olsr_u8_t index_stop,
          const olsr_u8_t *value)
{
  olsr_u16_t extend_length;

  olsr_pktbuf_append_u8(buf, type);
  olsr_pktbuf_append_u8(buf, tlv_semantics);

  //index start and stop
  if((tlv_semantics & NO_INDEX) == 0)
    {
      olsr_pktbuf_append_u8(buf, index_start);
      if((tlv_semantics & SINGLE_INDEX) == 0)
    olsr_pktbuf_append_u8(buf, index_stop);
    }

  //no value bit unset
  if((tlv_semantics & NO_VALUE) == 0)
    {
      //extend bit
      if((tlv_semantics & EXTENDED) == 0)
    olsr_pktbuf_append_u8(buf, length);
      else
    {
      extend_length = length;
      olsr_pktbuf_append_u16(buf, htons(extend_length));
    }
    }


  // value
  if((tlv_semantics & NO_VALUE) == 0)
    //olsr_pktbuf_append_u8(buf, value);
    olsr_pktbuf_append_byte_ary(buf, value, length);
  //multi value bit unsupported
}
}
