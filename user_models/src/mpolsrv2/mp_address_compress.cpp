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
   address compress
*/
#include <stdlib.h>
#include <string.h>
#include <assert.h>

//WIN FIX
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_olsr_debug.h"
#include "mp_olsr_conf.h"
#include "mp_def.h"
#include "mp_olsr_protocol.h"
#include "mp_address_compress.h"
#include "mp_tlv_compress.h"

#include "mp_olsr_util.h"
#include "mp_proc_link_set.h"
#include "mp_proc_mpr_set.h"

#include "mp_proc_adv_neigh_set.h"
#include "mp_proc_symmetric_neighbor_set.h"


#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

#define BYTE_TO_BIT 8

#define IP_PTR(ip)  ((IPV4_MODE) \
    ? ((char*)(&((ip)->v4))) \
    : ((char*)(&((ip)->v6.s6_addr_8))))

void breakpoint(void){

}

/* static function prototypes */
static void simple_address_compress(struct olsrv2*, olsr_pktbuf_t *,
    olsr_u8_t msg_type, BASE_ADDRESS *base);

static void build_not_covered(struct olsrv2* olsr, olsr_pktbuf_t *,
    olsr_u8_t msg_type, BASE_ADDRESS *base);
static void build_address_block(struct olsrv2* olsr, olsr_pktbuf_t *, ADDRESS_BLOCK *);


static BASE_ADDRESS *create_base_address_hello(struct olsrv2 *,
    union olsr_ip_addr *);
static BASE_ADDRESS *create_base_address_tc(struct olsrv2 *,
    union olsr_ip_addr *);
static BASE_ADDRESS *create_base_address_local_hello(struct olsrv2 *, union olsr_ip_addr *);
static BASE_ADDRESS *create_base_address_local_tc(struct olsrv2 *);

static void sort_base_address(struct olsrv2* olsr, BASE_ADDRESS *);
static void replace_base_address(BASE_ADDRESS *, olsr_u32_t, olsr_u32_t);
static OLSR_LIST *search_prefix_forward(struct olsrv2* olsr, BASE_ADDRESS *);
static OLSR_LIST *search_prefix_forward_for_local(struct olsrv2* olsr, BASE_ADDRESS *);

static OLSR_LIST *create_address_block(struct olsrv2* olsr,
                       OLSR_LIST *, BASE_ADDRESS *);

//free functions
static void free_base_address(BASE_ADDRESS *);
static void free_prefix_list(OLSR_LIST *);
static void free_address_block_list(OLSR_LIST *);



static BASE_ADDRESS *create_base_attached_network_address(struct olsrv2 *olsr);
static void build_not_covered_attached_network(struct olsrv2* olsr, olsr_pktbuf_t *,
    olsr_u8_t msg_type, BASE_ADDRESS *base);


//print functions

static void print_base_address(struct olsrv2 *olsr, BASE_ADDRESS *);
static void print_address_block(struct olsrv2 *olsr, olsr_u8_t *);
static void print_address_block_list(struct olsrv2 *olsr, OLSR_LIST *);


/* function implimentations */

/*
** Create {<addr-block> <tlv-block>}*
*/
void
address_compress(struct olsrv2 *olsr, olsr_pktbuf_t *buf,
    olsr_u8_t msg_type,
    olsr_u8_t compress_type, union olsr_ip_addr *local_iface_addr)
{
  switch (msg_type)
    {
    case HELLO_MESSAGE:
    case TC_MESSAGE:
    case LOCAL_ADDRESS_BLOCK:
      {
    BASE_ADDRESS *base=NULL;

    if(msg_type == HELLO_MESSAGE){
      base = create_base_address_hello(olsr, local_iface_addr);
    }else if(msg_type == TC_MESSAGE){
      base = create_base_address_tc(olsr, local_iface_addr);
    }else if(msg_type == LOCAL_ADDRESS_BLOCK && local_iface_addr == NULL){
      base = create_base_address_local_tc(olsr);
    }else if(msg_type == LOCAL_ADDRESS_BLOCK) {
      base = create_base_address_local_hello(olsr, local_iface_addr);
    }

    if(base == NULL){
      buf = NULL;
      return;
    }

    switch (compress_type)
    {
        case SIMPLE_COMPRESS:
        {
        if(DEBUG_OLSRV2)
        {
            olsr_printf("Simple Compress.\n");
        }

        simple_address_compress(olsr, buf, msg_type, base);
        break;
        }
        default:
        {
        if(DEBUG_OLSRV2)
        {
            olsr_printf("Unknown Compress Type.\n");
        }
        olsr_error("%s: no such compress_type\n");

        break;
        }
    }

    free_base_address(base);
    break;
      }
    default:
    {
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Unknown Message Type.\n");
        }
        olsr_error("%s: no such message_type\n");
    }
    }

}

BASE_ADDRESS *
create_base_address_local_tc(struct olsrv2 *olsr) {

  olsr_u32_t ifaddr_num, index;
  BASE_ADDRESS *base = NULL;

  //calculate number of interface addr
  ifaddr_num = 0;
  ifaddr_num = olsr->iface_num;

  base = (BASE_ADDRESS *)olsr_malloc(sizeof(BASE_ADDRESS), __FUNCTION__);
  base->size = ifaddr_num;

  base->data = (BLOCK_DATA *)olsr_malloc(sizeof(BLOCK_DATA) * base->size, __FUNCTION__);

  index = 0;

  for (index = 0; index < base->size; index++)
    {
      memset(&base->data[index].iface_addr, 0, sizeof(union olsr_ip_addr));
      if (olsr->olsr_cnf->ip_version == AF_INET)
    {
//Fix for Solaris
          /*olsr_ip4_copy((union olsr_ip_addr *)&base->data[index].iface_addr.v4,
            (union olsr_ip_addr *)&olsr->iface_addr[index].v4);*/
        olsr_ip_copy(olsr,
            (union olsr_ip_addr *)&base->data[index].iface_addr.v4,
            (union olsr_ip_addr *)&olsr->iface_addr[index].v4);
    }
      else
    {
//Fix for Solaris
        /*olsr_ip6_copy((union olsr_ip_addr *)&base->data[index].iface_addr.v6.s6_addr_8,
            (union olsr_ip_addr *)&olsr->iface_addr[index].v6);*/
        olsr_ip_copy(olsr,
            (union olsr_ip_addr *)&base->data[index].iface_addr.v6.s6_addr_8,
            (union olsr_ip_addr *)&olsr->iface_addr[index].v6.s6_addr_8);
    }
      base->data[index].covered = OLSR_FALSE;

      //invalid value
      base->data[index].link_status = 255;
      //WIN FIX: Changed the variable name
      //base->data[i].interfaceId = 255;
      base->data[index].other_if = 255;
      base->data[index].MPR_Selection = 255;
      base->data[index].Prefix_Length = 255;
      base->data[index].other_neigh = 255;
    }

  assert(ifaddr_num == index);

  if(DEBUG_OLSRV2)
  {
      print_base_address(olsr, base);
  }

  return base;
}



BASE_ADDRESS *
create_base_address_local_hello(struct olsrv2 *olsr, union olsr_ip_addr *sender)
{
  olsr_u32_t i;

  olsr_u32_t ifaddr_num, index;
  BASE_ADDRESS *base = NULL;

  //calculate number of interface addr
  ifaddr_num = 0;
  ifaddr_num = olsr->iface_num;

  base = (BASE_ADDRESS *)olsr_malloc(sizeof(BASE_ADDRESS), __FUNCTION__);
  base->size = ifaddr_num;

  base->data = (BLOCK_DATA *)olsr_malloc(sizeof(BLOCK_DATA) * base->size, __FUNCTION__);

  //sender interface
  memset(&base->data[0].iface_addr, 0, sizeof(union olsr_ip_addr));
  olsr_ip_copy(olsr,
           &base->data[0].iface_addr, sender);
  base->data[0].link_status = 255;
  base->data[0].other_if = 255;
  base->data[0].MPR_Selection = 255;
  base->data[0].Prefix_Length = 255;
  base->data[0].other_neigh = 255;
  base->data[0].covered = (olsr_bool)0;
  index = 1;

  for(i = 0; i < ifaddr_num; i++) {
    if(equal_ip_addr(olsr,
             &olsr->iface_addr[i], sender)) {
      continue;
    }
    // interface addr , except sender iface
    memset(&base->data[index].iface_addr, 0, sizeof(union olsr_ip_addr));
    if(olsr->olsr_cnf->ip_version == AF_INET) {
//Fix for Solaris
      /*olsr_ip4_copy((union olsr_ip_addr *)&base->data[index].iface_addr.v4,
            (union olsr_ip_addr *)&olsr->iface_addr[i].v4);*/
        olsr_ip_copy(olsr,
            (union olsr_ip_addr *)&base->data[index].iface_addr.v4,
            (union olsr_ip_addr *)&olsr->iface_addr[i].v4);
    }else {
//Fix for Solaris
      /*olsr_ip6_copy((union olsr_ip_addr *)&base->data[index].iface_addr.v6.s6_addr_8,
            (union olsr_ip_addr *)&olsr->iface_addr[i].v6);*/
      olsr_ip_copy(olsr,
          (union olsr_ip_addr *)&base->data[index].iface_addr.v6.s6_addr_8,
            (union olsr_ip_addr *)&olsr->iface_addr[i].v6.s6_addr_8);
    }
    base->data[index].link_status = 255;
    base->data[index].MPR_Selection = 255;
    base->data[index].Prefix_Length = 255;
    base->data[index].other_neigh = 255;
    base->data[index].covered = (olsr_bool)0;

    base->data[index].other_if = OLSR_TRUE;

    index++;
  }

  assert(ifaddr_num == index);

  if(DEBUG_OLSRV2)
  {
      print_base_address(olsr, base);
  }

  return base;
}

/*
** Create {<addr-block> <tlv-block>}*
 */
static void
simple_address_compress(struct olsrv2 *olsr, olsr_pktbuf_t *buf,
    olsr_u8_t msg_type, BASE_ADDRESS *base)
{
  OLSR_LIST *prefix_list = NULL;
  OLSR_LIST *address_block_list = NULL;
  OLSR_LIST_ENTRY *tmp = NULL;

  debug_code(print_base_address(olsr, base));

  if(msg_type == LOCAL_ADDRESS_BLOCK) {
      prefix_list = search_prefix_forward_for_local(olsr, base);
  }else {
      sort_base_address(olsr, base);
      prefix_list = search_prefix_forward(olsr, base);
  }

  address_block_list = create_address_block(olsr, prefix_list, base);

  debug_code(print_address_block_list(olsr, address_block_list));

  for (tmp = address_block_list->head; tmp != NULL; tmp = tmp->next)
    {
      ADDRESS_BLOCK *const data_address_block = (ADDRESS_BLOCK *)tmp->data;

      // <addr-block>
      build_address_block(olsr, buf, data_address_block);

      // <tlv-block>
      switch (msg_type)
    {
    case HELLO_MESSAGE:
      build_tlv_hello_by_list(olsr, buf, &data_address_block->block);
      break;
    case TC_MESSAGE:
      build_tlv_block_tc(buf);
      break;
    case LOCAL_ADDRESS_BLOCK:
      //      build_tlv_block_local(buf);
      build_tlv_local_by_list(olsr, buf, &data_address_block->block);
      break;
    default:
      olsr_error("Unknown message type");
    }
    }

  // build not covered message
  build_not_covered(olsr, buf, msg_type, base);

  free_address_block_list(address_block_list);
  free_prefix_list(prefix_list);
}



void
build_not_covered_attached_network(struct olsrv2* olsr, olsr_pktbuf_t *buf, olsr_u8_t msg_type, BASE_ADDRESS *base)
{
  size_t i;

  for (i = 0; i < base->size; i++)
    {
      if (base->data[i].covered)
    continue;

      base->data[i].covered = OLSR_TRUE;

      // <addr-block>
      olsr_pktbuf_append_u8(buf, 1);    // <num_addr>
      olsr_pktbuf_append_u8(buf, NO_TAIL);  // <head-length> no tail bit set

      olsr_pktbuf_append_ip(olsr, buf, &base->data[i].iface_addr);  // <mid>

      debug_code(print_address_block(olsr, buf->data));

      switch (msg_type)
    {
    case TC_MESSAGE:
      //build_tlv_block_for_index_tc(buf,base,0);
      build_tlv_block_for_index_attached_network(buf, base, (unsigned int)i);
      break;

    default:
      olsr_error("Unknown message type");
    }
    }

}

/*
 * XXX
 */
void
build_not_covered(struct olsrv2* olsr, olsr_pktbuf_t *buf, olsr_u8_t msg_type, BASE_ADDRESS *base)
{
  size_t i;

  for (i = 0; i < base->size; i++)
    {
      if (base->data[i].covered)
    continue;

      base->data[i].covered = OLSR_TRUE;

      // <addr-block>
      olsr_pktbuf_append_u8(buf, 1);    // <num_addr>
      olsr_pktbuf_append_u8(buf, NO_TAIL);  // <head-length> no tail bit set

      olsr_pktbuf_append_ip(olsr, buf, &base->data[i].iface_addr);  // <mid>

      debug_code(print_address_block(olsr, buf->data));

      switch (msg_type)
    {
    case HELLO_MESSAGE:
      build_tlv_block_for_index_hello(buf, base, (unsigned int)i);
      break;
    case TC_MESSAGE:
      build_tlv_block_tc(buf);
      break;
    case LOCAL_ADDRESS_BLOCK:
      //build_tlv_block_local(buf);
      build_tlv_block_for_index_local(buf, base, (unsigned int)i);
      break;
    default:
      olsr_error("Unknown message type %d", msg_type);
    }
    }

}

/*
 * Create <addr-block>.
 *
 * <addr-block> = <head-length> <head> <num-tails> <tail>+
 */
static void
build_address_block(struct olsrv2* olsr, olsr_pktbuf_t *buf, ADDRESS_BLOCK *address_block)
{
  const size_t head_len = address_block->prefix.prefix_size;
  const size_t tail_len = olsr->olsr_cnf->ipsize - head_len;
  size_t head_octet;

  head_octet = head_len + NO_TAIL; // no tail bit set

  OLSR_LIST_ENTRY *p;

  // <num-addr>//update 0913
  olsr_pktbuf_append_u8(buf, (olsr_u8_t)address_block->block.numEntry);

  // <head-length>
  olsr_pktbuf_append_u8(buf, (olsr_u8_t)head_octet);
  // <head>
  olsr_pktbuf_append_byte_ary(buf, address_block->prefix.prefix, head_len);

  // <mid>
  for (p = address_block->block.head; p != NULL; p = p->next)
    {
      BLOCK_DATA *data = (BLOCK_DATA *)p->data;
      olsr_u8_t *ip = (olsr_u8_t *)&data->iface_addr;
      olsr_pktbuf_append_byte_ary(buf, ip + head_len, tail_len);
    }
}

static BLOCK_DATA *search_base_address_for_addr(struct olsrv2* olsr,
                        BASE_ADDRESS *base,
                        olsr_u32_t index,
                        union olsr_ip_addr *addr)
{
  olsr_u32_t i;
  BLOCK_DATA *data = NULL, *ret_data = NULL;

  if(base == NULL)
    return NULL;

  for(i = 0; i < index; i++) {
    data = (BLOCK_DATA *)&base->data[i];

    if(equal_ip_addr(olsr,
             &data->iface_addr, addr)) {
      ret_data = data;
      break;
    }
  }

  return ret_data;
}

BASE_ADDRESS *
create_base_address_hello(struct olsrv2 *olsr,
              union olsr_ip_addr *local_iface_addr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_LINK_TUPLE *link_data = NULL;
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *sym_data = NULL;
  olsr_u32_t index, i;
  BASE_ADDRESS *base = NULL;
  BLOCK_DATA *ret_data = NULL;
  olsr_time_t time;
  get_current_time(olsr, &time);


  base = (BASE_ADDRESS *)olsr_malloc(sizeof(BASE_ADDRESS), __FUNCTION__);
  base->size = olsr->link_set.numEntry;
  for(i = 0; i < HASHSIZE; i++) {
    base->size += olsr->sym_neigh_set[i].list.numEntry;
  }

  if(base->size == 0)
    {
      free(base);
      return NULL;
    }

  base->data = (BLOCK_DATA *)olsr_malloc(sizeof(BLOCK_DATA) * base->size, __FUNCTION__);

  tmp = olsr->link_set.head;

  index = 0;
  while (tmp)
    {
      link_data = (OLSR_LINK_TUPLE *)tmp->data;

      if (equal_ip_addr(olsr,
            &link_data->L_local_iface_addr, local_iface_addr))
    {

      olsr_ip_copy(olsr, &base->data[index].iface_addr,
               &link_data->L_neighbor_iface_addr);

      base->data[index].link_status = (olsr_u8_t) get_link_status(time,
                                                link_data->L_SYM_time,
                                                link_data->L_ASYM_time,
                                                link_data->L_LOST_LINK_time);

      //WIN FIX: Changed the variable name
      //base->data[index].interfaceId = TransmittingInterface;
      if(search_mpr_set_for_exist(olsr, &link_data->L_local_iface_addr,
                      &link_data->L_neighbor_iface_addr) == OLSR_TRUE)
        {
          base->data[index].MPR_Selection = OLSR_TRUE;

        }else{
          base->data[index].MPR_Selection = 255;
      }

      base->data[index].covered = OLSR_FALSE;
      //invalid
      base->data[index].Prefix_Length = 255;
      base->data[index].other_if = 255;
      base->data[index].other_neigh = 255;


       index++;
    }
      tmp = tmp->next;
    }


  //For each address which appears as an N_neighbor_iface_addr
  //in one or more Symmetric Neighbor Tuples:...
  for(i = 0; i < HASHSIZE; i++) {
    tmp = olsr->sym_neigh_set[i].list.head;

    while(tmp) {
      sym_data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)tmp->data;

      ret_data =
    search_base_address_for_addr(olsr,
                     base, index,
                     &sym_data->N_neighbor_iface_addr);

      if(ret_data) {
    //5.2.1 & (5.2.2 & 5.2.3 already set) //xxxx
    if(ret_data->link_status == SYMMETRIC ||
       ret_data->other_neigh == SYMMETRIC ||
       (ret_data->other_neigh == LOST && ret_data->link_status == LOST)) {
      tmp = tmp->next;
      continue;
    }
    //5.2.2 (update)
    else {
      olsr_u8_t tmpNeighStatus = (olsr_u8_t) get_neighbor_status(&time,
                                                &sym_data->N_SYM_time);
      if(tmpNeighStatus == SYMMETRIC) {
        ret_data->other_neigh = SYMMETRIC;
      }
    }

      }
      //5.2.2 & 5.2.3
      else {
    olsr_ip_copy(olsr,
             &base->data[index].iface_addr,
             &sym_data->N_neighbor_iface_addr);
    base->data[index].other_neigh = (olsr_u8_t) get_neighbor_status(&time,
                                                    &sym_data->N_SYM_time);
    base->data[index].covered = OLSR_FALSE;

    base->data[index].link_status = 255;
    base->data[index].Prefix_Length = 255;
    base->data[index].MPR_Selection = 255;
      //WIN FIX: Changed the variable name
    //base->data[index].interfaceId = 255;
    base->data[index].other_if = 255;
    index++;
      }
      tmp = tmp->next;
    }
  }



  //xxx
  base->size = index;

  return base;
}

BASE_ADDRESS *
create_base_address_tc(struct olsrv2 *olsr,
               union olsr_ip_addr *local_iface_addr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ADV_NEI_TUPLE *adv_nei_data = NULL;
  olsr_u32_t index;
  BASE_ADDRESS *base = NULL;


  base = (BASE_ADDRESS *)olsr_malloc(sizeof(BASE_ADDRESS), __FUNCTION__);

  base->size = olsr->adv_neigh_set.numEntry;

  base->data = (BLOCK_DATA *)olsr_malloc(sizeof(BLOCK_DATA) * base->size, __FUNCTION__);

  tmp = olsr->adv_neigh_set.head;

  index = 0;
  while (tmp)
    {
      adv_nei_data = (OLSR_ADV_NEI_TUPLE *)tmp->data;

      olsr_ip_copy(olsr,
           &base->data[index].iface_addr,
           &adv_nei_data->A_neighbor_iface_addr);

      base->data[index].covered = (olsr_bool)0;

      //invalid value
      base->data[index].link_status = 255;
      //WIN FIX: Changed the variable name
      //base->data[index].interfaceId = 255;
      base->data[index].other_if = 255;
      base->data[index].MPR_Selection = 255;
      base->data[index].Prefix_Length = 255;
      base->data[index].other_neigh = 255;


      index++;
      tmp = tmp->next;
    }

  assert(olsr->adv_neigh_set.numEntry == index);

  if (DEBUG_OLSRV2)
  {
      print_base_address(olsr, base);
  }

  return base;
}



static OLSR_LIST *
create_address_block(struct olsrv2* olsr,
             OLSR_LIST *prefix_list, BASE_ADDRESS *base)
{
  OLSR_LIST *list = NULL;
  OLSR_LIST_ENTRY *tmp_prefix = NULL;

  PREFIX *data_prefix = NULL;

  olsr_u32_t j;

  list = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  breakpoint();
  OLSR_InitList(list);

  tmp_prefix = prefix_list->head;
  while (tmp_prefix)
    {
      ADDRESS_BLOCK address_block;
      BLOCK_DATA data_block;

      data_prefix = (PREFIX *)tmp_prefix->data;
      data_prefix->union_num = 0;

      address_block.prefix.prefix =
    (olsr_u8_t *)olsr_malloc(sizeof(olsr_u8_t)*data_prefix->prefix_size, __FUNCTION__);
      memcpy(address_block.prefix.prefix, data_prefix->prefix,
         data_prefix->prefix_size);
      address_block.prefix.prefix_size = data_prefix->prefix_size;
      address_block.prefix.union_num = data_prefix->union_num;

      OLSR_InitList(&address_block.block);

      for (j = 0; j < base->size; j++)
        {

          if (olsr->olsr_cnf->ip_version == AF_INET)
            {
              if (!base->data[j].covered &&
              memcmp(data_prefix->prefix,
                 &base->data[j].iface_addr.v4,
                 data_prefix->prefix_size) == 0)
            {
              base->data[j].covered = OLSR_TRUE;

              address_block.prefix.union_num++;

              olsr_ip_copy(olsr,
                       &data_block.iface_addr,
                       &base->data[j].iface_addr);
              data_block.link_status = base->data[j].link_status;
              data_block.other_neigh = base->data[j].other_neigh;
              //WIN FIX: Changed the variable name
              //data_block.InterfaceId = base->data[j].InterfaceId;
              data_block.other_if = base->data[j].other_if;
              data_block.MPR_Selection = base->data[j].MPR_Selection;
              data_block.Prefix_Length = base->data[j].Prefix_Length;
              data_block.covered = base->data[j].covered;

              OLSR_InsertList(&address_block.block, &data_block,
                      sizeof(BLOCK_DATA));
            }
            }
          else
            {
              if (!base->data[j].covered &&
              memcmp(data_prefix->prefix,
                 &base->data[j].iface_addr.v6.s6_addr_8,
                 data_prefix->prefix_size) == 0)
            {
              base->data[j].covered = OLSR_TRUE;

              address_block.prefix.union_num++;

              olsr_ip_copy(olsr,
                       &data_block.iface_addr,
                       &base->data[j].iface_addr);
              data_block.link_status = base->data[j].link_status;
              //WIN FIX: Changed the variable name
              //data_block.InterfaceId = base->data[j].InterfaceId;
              data_block.other_if = base->data[j].other_if;
              data_block.other_neigh = base->data[j].other_neigh;
              data_block.MPR_Selection = base->data[j].MPR_Selection;
              data_block.Prefix_Length = base->data[j].Prefix_Length;
              data_block.covered = base->data[j].covered;

              OLSR_InsertList(&address_block.block, &data_block,
                      sizeof(BLOCK_DATA));
        }
        }
    }
      OLSR_InsertList(list, &address_block, sizeof(ADDRESS_BLOCK));

      tmp_prefix = tmp_prefix->next;
    }
  return list;
}

static OLSR_LIST *search_prefix_forward_for_local(struct olsrv2* olsr,
                          BASE_ADDRESS *base) {
  OLSR_LIST *list = NULL;
  olsr_u32_t current_bytes;
  olsr_u32_t union_num = 1;
  PREFIX insert_data;
  olsr_u32_t i;

  list = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  OLSR_InitList(list);

  if(base->size == 1) {
    return list;
  }

  current_bytes = (olsr_u32_t)olsr->olsr_cnf->ipsize;
  while (current_bytes > 0) {
    for (i = 1; i < base->size; i++) {
      union_num = 1;

      if (memcmp(&base->data[0].iface_addr,
         &base->data[i].iface_addr, current_bytes) == 0) {
    union_num++;
      }
    }
    //local interface block must be created in 1 address block
    if(union_num == base->size) {
      break;
    }
    current_bytes--;
  }

  if(current_bytes == 0) {
    insert_data.prefix = NULL;
    insert_data.prefix_size = current_bytes;

  }else {
    insert_data.prefix = (olsr_u8_t *)olsr_malloc(current_bytes,
                          __FUNCTION__);
    insert_data.prefix_size = current_bytes;

    memcpy(insert_data.prefix, &base->data[0].iface_addr.v4,
       insert_data.prefix_size);

  }
  insert_data.union_num = base->size;
  OLSR_InsertList(list, &insert_data, sizeof(PREFIX));

  return list;
}

/*
 *
 */
static OLSR_LIST *
search_prefix_forward(struct olsrv2* olsr, BASE_ADDRESS *base)
{
  OLSR_LIST *list = NULL;
  OLSR_LIST_ENTRY *tmp = NULL;
  olsr_u32_t current_bytes;
  olsr_u32_t union_num;
  olsr_u32_t i;
  olsr_u32_t j;
  olsr_bool exist = OLSR_FALSE;

  list = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  OLSR_InitList(list);

  current_bytes = (olsr_u32_t)olsr->olsr_cnf->ipsize ;
  while (current_bytes > 0)
    {
    if(DEBUG_OLSRV2)
    {
        olsr_printf("%d [bytes] in search_prefix_forward\n", current_bytes);
    }

      for (i = 0; i < base->size; i++)
    {
      union_num = 1;

      for (j = 0; j < base->size; j++)
        {
          if (i == j)
        continue;

          if (memcmp(&base->data[i].iface_addr,
             &base->data[j].iface_addr, current_bytes) == 0)
        {
          union_num++;

          exist = OLSR_FALSE;

          // check covered
          tmp = list->head;
          while (tmp)
            {
              PREFIX *data = (PREFIX *)tmp->data;

              if (memcmp(data->prefix, &base->data[i].iface_addr,
                 current_bytes) == 0)
            {
              if (current_bytes == data->prefix_size)
                data->union_num = union_num;
              exist = OLSR_TRUE;
            }

              tmp = tmp->next;
            }

          //insert prefix
          if (!exist)
            {
              PREFIX insert_data;

              insert_data.prefix =
            (olsr_u8_t *)olsr_malloc(current_bytes, __FUNCTION__);

              insert_data.prefix_size = current_bytes;

              memcpy(insert_data.prefix,
                 &base->data[i].iface_addr.v4,
                 insert_data.prefix_size);
              insert_data.union_num = 0;

              OLSR_InsertList(list, &insert_data, sizeof(PREFIX));
            }
        }
        }
    }
      current_bytes--;
    }

  if(DEBUG_OLSRV2)
  {
      if (olsr->olsr_cnf->ip_version == AF_INET)
      {
      char str[INET_ADDRSTRLEN];
      union olsr_ip_addr addr;
      tmp = list->head;
      while (tmp)
      {
          PREFIX *const data = (PREFIX *)tmp->data;
//Fix For Solaris
          memset(&addr.v4, 0, sizeof(olsr_u32_t));
          memcpy(&addr.v4, data->prefix, data->prefix_size);
          /*inet_ntop(AF_INET, &addr.v4, str, sizeof(str));
          */
          ConvertIpv4AddressToString(addr.v4,str);
          olsr_printf("prefix = %s, prefix_size = %d, union_num = %d\n",
             str, data->prefix_size, data->union_num);
          tmp = tmp->next;
      }
      }
  }

  return list;
}


static void
sort_base_address(struct olsrv2* olsr,
          BASE_ADDRESS *base)
{
  olsr_u32_t i, j;

  //Bubble sort
  if (base->size > 0)
    {
      for (i = 0; i < base->size - 1; i++)
    {
      for (j = i + 1; j < base->size; j++)
        {
          if (cmp_ip_addr(olsr,
                  &base->data[i].iface_addr,
                  &base->data[j].iface_addr) > 0)
        {
          replace_base_address(base, i, j);
        }
        }
    }
    }
}

void
replace_base_address(BASE_ADDRESS *base, olsr_u32_t i, olsr_u32_t j)
{
  union olsr_ip_addr tmp_addr;
  olsr_u8_t tmp_link, tmp_if, tmp_mpr, tmp_prefix;
  olsr_bool tmp_covered;

  tmp_addr = base->data[i].iface_addr;
  base->data[i].iface_addr = base->data[j].iface_addr;
  base->data[j].iface_addr = tmp_addr;

  tmp_link = base->data[i].link_status;
  base->data[i].link_status = base->data[j].link_status;
  base->data[j].link_status = tmp_link;

  //WIN FIX: Changed the variable name
  //tmp_if = base->data[i].interfaceId;
  //base->data[i].interfaceId = base->data[j].interfaceId;
  tmp_if = base->data[i].other_if;
  base->data[i].other_if = base->data[j].other_if;
  base->data[j].other_if = tmp_if;

  tmp_if = base->data[i].other_neigh;
  base->data[i].other_neigh = base->data[j].other_neigh;
  base->data[j].other_neigh = tmp_if;

  tmp_mpr = base->data[i].MPR_Selection;
  base->data[i].MPR_Selection = base->data[j].MPR_Selection;
  base->data[j].MPR_Selection = tmp_mpr;


  tmp_prefix = base->data[i].Prefix_Length;
  base->data[i].Prefix_Length = base->data[j].Prefix_Length;
  base->data[j].Prefix_Length = tmp_prefix;


  tmp_covered = base->data[i].covered;
  base->data[i].covered = base->data[j].covered;
  base->data[j].covered = tmp_covered;
}

void
free_base_address(BASE_ADDRESS *base)
{
  //free base_address
  free(base->data);
  free(base);
}

void
free_address_block_list(OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  ADDRESS_BLOCK *data_address_block = NULL;
  PREFIX *data_prefix = NULL;

  tmp = list->head;
  while (tmp)
    {
      data_address_block = (ADDRESS_BLOCK *)tmp->data;

      data_prefix = &data_address_block->prefix;
      free(data_prefix->prefix);

      OLSR_DeleteList_Static(&data_address_block->block);

      tmp = tmp->next;
    }

  OLSR_DeleteList(list);
}

void
free_prefix_list(OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  PREFIX *data = NULL;

  tmp = list->head;
  while (tmp)
    {
      data = (PREFIX *)tmp->data;

      free(data->prefix);

      tmp = tmp->next;
    }
  OLSR_DeleteList(list);
}


void
print_base_address(struct olsrv2 *olsr, BASE_ADDRESS *base)
{
  olsr_u32_t i;

  if(olsr->olsr_cnf->debug_level < 5)
      return;

  olsr_printf("\n********************\n");
  olsr_printf("[Base Addresses]\n");
  if (base)
    {
      for (i = 0; i < base->size; i++)
    {
        char* paddr = olsr_niigata_ip_to_string(olsr, &base->data[i].iface_addr);
        olsr_printf("%s\t", paddr);
        free(paddr);

      if (base->data[i].link_status != 255)
        {
          olsr_printf("link_status = ");
          print_link_status(base->data[i].link_status);
          olsr_printf("\t");
        }
      else
        olsr_printf("link_status = invalid\t");
      if(base->data[i].other_neigh != 255) {
        olsr_printf("other_neigh = ");
        print_other_neigh_status(base->data[i].other_neigh);
        olsr_printf("\t");
      }
      else
        olsr_printf("other_neigh = invalid\t");

      //WIN FIX: Changed the variable name
      //if (base->data[i].interfaceId != 255)
      if (base->data[i].other_if != 255)
        {
          olsr_printf("OTHER_IF = ");
          //print_interface(base->data[i].interfaceId);
          print_interface(base->data[i].other_if);
          olsr_printf("\t");
        }
      else
        olsr_printf("OTHER_IF = invalid\t");

      if (base->data[i].MPR_Selection != 255)
        {
          olsr_printf("MPR_Selection = ");
          print_mpr_selection((olsr_bool)base->data[i].MPR_Selection);
          olsr_printf("\t");
        }
      else
        olsr_printf("MPR_Selection = invalid\t");


      if (base->data[i].Prefix_Length != 255)
        {
          olsr_printf("Prefix_Length = %u\n",base->data[i].Prefix_Length);
          olsr_printf("\t");
        }
      else
        olsr_printf("Prefix_Length = invalid\t");



      olsr_printf("covered = %d\n", base->data[i].covered);
    }
    }
  olsr_printf("********************\n");
}


static
void
print_address_block(struct olsrv2 *olsr, olsr_u8_t *msg)
{
  olsr_u8_t *tmp = NULL;

  olsr_u8_t *head = NULL, *tail = NULL;
  olsr_u8_t zero_tail, no_tail;
  olsr_u8_t num_addr, head_octet, tail_octet,head_length, tail_length, mid_length;
  union olsr_ip_addr mask, mid;

  olsr_u32_t i;


  if(olsr->olsr_cnf->debug_level < 4)
    return;

  if (msg == NULL)
    return;

  tmp = msg;
  head = tail = NULL;

  num_addr = *(olsr_u8_t *)tmp;
  tmp += sizeof(olsr_u8_t);

  head_octet = *(olsr_u8_t *)tmp;
  tmp += sizeof(olsr_u8_t);

  head_length = head_octet & GET_HEAD_LENGTH;
  no_tail = head_octet & NO_TAIL;

  if(head_length !=0){

      head = tmp;
    tmp += head_length;
  }

  if(no_tail == 0){
    tail_octet = *(olsr_u8_t *)tmp;
    tail_length = tail_octet & GET_TAIL_LENGTH;
    zero_tail = tail_octet & ZERO_TAIL;
    tmp += sizeof(olsr_u8_t);

    tail = tmp;
    tmp += tail_length;
  }else{
    tail_octet = 0;
    tail_length = 0;
    zero_tail = 1;
  }

  //mid_length = ipsize - head_length - tail_length;
  mid_length = (olsr_u8_t)olsr->olsr_cnf->ipsize - head_length - tail_length;

  olsr_printf("\n********************\n");
  olsr_printf("[Address Block]\n");
  olsr_printf("head_length = %d [bytes]\n", head_length);

  if (head_length > 0)
    {
      memset(&mask, 0, sizeof(union olsr_ip_addr));

      if (olsr->olsr_cnf->ip_version == AF_INET){
    memcpy(&mask.v4, head, head_length);
    memcpy(&mask.v4 + head_length +mid_length, tail, tail_length);
      }else if (olsr->olsr_cnf->ip_version == AF_INET6){
    memcpy(mask.v6.s6_addr_8, head, head_length);
    memcpy(mask.v6.s6_addr_8+ head_length + mid_length, tail, tail_length);
      }else
    olsr_error("Un known ip_version.\n");

      char* paddr = olsr_niigata_ip_to_string(olsr, &mask);
      olsr_printf("head = %s\n", paddr);
      free(paddr);
    }

  olsr_printf("number of address = %d\n", num_addr);

  for (i = 0; i < num_addr; i++)
    {
      memset(&mid, 0, sizeof(union olsr_ip_addr));

      if (olsr->olsr_cnf->ip_version == AF_INET)
    {
      memcpy(&mid.v4 + head_length, tmp, mid_length);
      char* addr = olsr_niigata_ip_to_string(olsr, &mid);
      olsr_printf("%-16s",addr);
      free(addr);

      if (head_length > 0)
        {
          memcpy(&mask.v4 + head_length, tmp, mid_length);
          char* paddr = olsr_niigata_ip_to_string(olsr, &mask);
          olsr_printf("\t%-16s\n", paddr);
          free(paddr);
        }
      else
        olsr_printf("\n");

      tmp += mid_length;

    }
      else if (olsr->olsr_cnf->ip_version == AF_INET6)
    {

      memcpy(&mid.v6.s6_addr_8 + head_length, tmp, mid_length);
      char* paddr = olsr_niigata_ip_to_string(olsr, &mid);
      olsr_printf("\t%-16s\n", paddr);
      free(paddr);

      if (head_length > 0)
        {
          memcpy(mask.v6.s6_addr_8 + head_length, tmp, mid_length);

          char* paddr = olsr_niigata_ip_to_string(olsr, &mask);
          olsr_printf("\t%-16s\n", paddr);
          free(paddr);
        }
      else
        olsr_printf("\n");

      tmp += mid_length;
    }
    }

  olsr_printf("********************\n");
}

static
void
print_address_block_list(struct olsrv2 *olsr, OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *tmp_list = NULL, *tmp_block = NULL;

  ADDRESS_BLOCK *data_address_block = NULL;
  PREFIX *data_prefix = NULL;
  BLOCK_DATA *data_block = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp_list = list->head;
  while (tmp_list)
    {
      data_address_block = (ADDRESS_BLOCK *)tmp_list->data;

      data_prefix = &data_address_block->prefix;

      if(data_prefix == NULL)
    break;

      olsr_printf("**************** [address_block] ***************\n");
      if (olsr->olsr_cnf->ip_version == AF_INET)
    {
      union olsr_ip_addr addr;

      memset(&addr.v4, 0, sizeof(olsr_u32_t));
      memcpy(&addr.v4, data_prefix->prefix, data_prefix->prefix_size);

      char* paddr = olsr_niigata_ip_to_string(olsr, &addr);
      olsr_printf("prefix = %-16s\nprefix_size = %3d\nunion_num = %3d\n",
         paddr,
         data_prefix->prefix_size, data_prefix->union_num);
      free(paddr);
    }
      else
    {
      union olsr_ip_addr addr;

      memset(&addr.v6.s6_addr_8, 0, 4 * sizeof(olsr_u32_t));
      memcpy(&addr.v6.s6_addr_8, data_prefix->prefix,
          data_prefix->prefix_size);

      char* paddr = olsr_niigata_ip_to_string(olsr, &addr);
      olsr_printf("prefix = %-46s\nprefix_size = %3d\nunion_num = %3d\n",
         paddr,
         data_prefix->prefix_size, data_prefix->union_num);
      free(paddr);
    }

      tmp_block = data_address_block->block.head;
      while (tmp_block)
    {
      data_block = (BLOCK_DATA *)tmp_block->data;

      if (olsr->olsr_cnf->ip_version == AF_INET)
        {
          union olsr_ip_addr addr;
//Fix for Solaris
          /*olsr_ip4_copy((union olsr_ip_addr *)&addr.v4,
                (union olsr_ip_addr *)&data_block->iface_addr.v4);*/
          olsr_ip_copy(olsr,
              (union olsr_ip_addr *)&addr.v4,
                (union olsr_ip_addr *)&data_block->iface_addr.v4);

          char* paddr = olsr_niigata_ip_to_string(olsr, &addr);
          olsr_printf("\tiface_addr = %-16s\n",paddr);
          free(paddr);
        }
      else
        {
          union olsr_ip_addr addr;
//Fix for Solaris
         /*olsr_ip6_copy((union olsr_ip_addr *)&addr.v6.s6_addr_8,
               (union olsr_ip_addr *)&data_block->iface_addr.v6.s6_addr_8);*/
          olsr_ip_copy(olsr,
              (union olsr_ip_addr *)&addr.v6.s6_addr_8,
                (union olsr_ip_addr *)&data_block->iface_addr.v6.s6_addr_8);

          char* paddr = olsr_niigata_ip_to_string(olsr, &addr);
          olsr_printf("\tiface_addr = %-46s\n",paddr);
          free(paddr);
        }

      if (data_block->link_status != 255)
        {
          olsr_printf("\tlink_status = ");
          print_link_status(data_block->link_status);
          olsr_printf("\n");
        }
      else
        olsr_printf("\tlink_status = invalid\n");

      if(data_block->other_neigh != 255)
        {
          olsr_printf("\tother_neigh = ");
          print_other_neigh_status(data_block->other_neigh);
          olsr_printf("\n");
        }
      else
        olsr_printf("\tother_neigh = invalid\n");

      if (data_block->other_if != 255)
        {
          olsr_printf("\tOTHER_IF = ");
          print_interface(data_block->other_if);
          olsr_printf("\n");
        }
      else
        olsr_printf("\tOTHER_IF = invalid\n");

      if (data_block->MPR_Selection != 255)
        {
          olsr_printf("\tMPR_Selection = ");
          print_mpr_selection((olsr_bool)data_block->MPR_Selection);
          olsr_printf("\n");
        }
      else
        olsr_printf("\tMPR_Selection = invald\n");


      olsr_printf("\tcovered = %d\n\n", data_block->covered);

      tmp_block = tmp_block->next;
    }

      olsr_printf("************************************************\n");

      tmp_list = tmp_list->next;
    }
}




static BASE_ADDRESS *create_base_attached_network_address(struct olsrv2 *olsr)
{
  BASE_ADDRESS *base = NULL;
  ATTACHED_NETWORK *addr = olsr->attached_net_addr;
  int index = 0;

  base = (BASE_ADDRESS *)olsr_malloc(sizeof(BASE_ADDRESS), __FUNCTION__);
  base->size = olsr->advNetAddrNum;

  base->data = (BLOCK_DATA *)olsr_malloc(sizeof(BLOCK_DATA) * base->size, __FUNCTION__);

  while(addr)
    {
      olsr_ip_copy(olsr,
           &base->data[index].iface_addr,
           &addr->network_addr);

      base->data[index].covered = (olsr_bool)0;
      base->data[index].Prefix_Length = addr->prefix_length;

      //invalid value
      base->data[index].link_status = 255;
      base->data[index].other_if = 255;
      base->data[index].MPR_Selection = 255;
      base->data[index].other_neigh = 255;

      addr = addr->next;
      index++;
    }

  if(DEBUG_OLSRV2)
  {
      print_base_address(olsr, base);
  }
  return base;
}

static void  simple_address_compress_attached_network_address(struct olsrv2* olsr,
                                  olsr_pktbuf_t *buf,
                                  olsr_u8_t msg_type,
                                  BASE_ADDRESS *base)
{
  OLSR_LIST *prefix_list = NULL;
  OLSR_LIST *address_block_list = NULL;
  OLSR_LIST_ENTRY *tmp = NULL;

  sort_base_address(olsr, base);

  if(DEBUG_OLSRV2)
  {
      print_base_address(olsr, base);
  }
  prefix_list = search_prefix_forward(olsr, base);
  address_block_list = create_address_block(olsr, prefix_list, base);

  debug_code(print_address_block_list(olsr, address_block_list));

  for (tmp = address_block_list->head; tmp != NULL; tmp = tmp->next)
    {
      ADDRESS_BLOCK *const data_address_block = (ADDRESS_BLOCK *)tmp->data;
      // <addr-block>
      build_address_block(olsr, buf, data_address_block);

      // <tlv-block>
      switch (msg_type)
    {
    case TC_MESSAGE:
      build_tlv_attached_network_by_list(olsr, buf, &data_address_block->block);
      break;
    default:
      olsr_error("Unknown message type");
    }
    }

    // build not covered message
  build_not_covered_attached_network(olsr, buf, msg_type, base);

  free_address_block_list(address_block_list);
  free_prefix_list(prefix_list);
}


void create_attached_network_address_block(struct olsrv2 *olsr,
                       olsr_pktbuf_t *buf,
                       olsr_u8_t msg_type,
                       olsr_u8_t compress_type,
                       union olsr_ip_addr *local_iface_addr)
{
  //skip creating attached_network address
  if(olsr->attached_net_addr == NULL)
    return;

  switch(msg_type)
    {
    case TC_MESSAGE:
      {
    BASE_ADDRESS *base = NULL;
    base = create_base_attached_network_address(olsr);

    switch(compress_type)
    {
      case SIMPLE_COMPRESS:
        {
        if(DEBUG_OLSRV2)
        {
            olsr_printf("Simple Compress.\n");
        }
        simple_address_compress_attached_network_address(olsr, buf, msg_type, base);
        break;
        }
      default:
      {
          if(DEBUG_OLSRV2)
          {
          olsr_printf("Unknown compress type.\n");
          }
          olsr_error("%s: no such compress_type\n");
      }
    }
    free_base_address(base);
    break;
      }

    default:
    {
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Unknown message type.\n");
        }
        olsr_error("%s: no such message_type\n");
    }
    }
}
}
