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
#include "mp_proc_rcv_msg_set.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

//WIN FIX
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_olsr_conf.h"
#include "mp_def.h"
#include "mp_olsr_debug.h"
#include "mp_olsr_util.h"

#include "mp_proc_link_set.h"
#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{


/* static function prototypes */
static
void insert_rcv_msg_set(struct olsrv2 *olsr,
            union olsr_ip_addr orig_addr,
            olsr_u16_t seq_number,
            olsr_u8_t type);
static
OLSR_LIST *
search_rcv_msg_set(struct olsrv2 *olsr,
           union olsr_ip_addr orig_addr,
           olsr_u16_t seq_number,
           olsr_u8_t type);
static
olsr_bool delete_rcv_msg_set_for_timeout_handler(void *, void *, void *);
static
olsr_bool search_rcv_msg_set_handler(void *, void *, void *);

/* function implimentations */
void init_rcv_msg_set(struct olsrv2 *olsr)
{
  //struct olsrv2_struct
  olsr->change_rcv_msg_set = OLSR_FALSE;
  OLSR_InitHashList(olsr->rcv_msg_set);
}

olsr_bool proc_rcv_msg_set(struct olsrv2 *olsr,
               union olsr_ip_addr* source_addr,
               const struct message_header *m)
{
  OLSR_LIST *retList = NULL;
  olsr_u8_t type;

  retList = search_link_set_for_symmetric(olsr, source_addr);

  if(!retList)
  {
      return OLSR_FALSE;
  }
  else
  {
      OLSR_DeleteList_Search(retList);
  }

  //4.4
  if((m->semantics & 0x02) == 0){ //bit 2
    type = 0;
  }
  else{
    type = m->message_type;
  }

  retList = search_rcv_msg_set(olsr,
                m->orig_addr,
                m->message_seq_num,
                type);


  //4.4.1
  if(retList == NULL){
    insert_rcv_msg_set(olsr,
               m->orig_addr,
               m->message_seq_num,
               type);

    //struct olsrv2
    olsr->change_rcv_msg_set = OLSR_TRUE;
    return OLSR_TRUE;
  }else{
    OLSR_DeleteList_Search(retList);
    return OLSR_FALSE;
  }
}

void insert_rcv_msg_set(struct olsrv2 *olsr,
            union olsr_ip_addr orig_addr,
            olsr_u16_t seq_number,
            olsr_u8_t type)
{
  OLSR_RCV_MSG_TUPLE data;

  data.RX_type = type;
  data.RX_addr = orig_addr;
  data.RX_seq_number = seq_number;

  get_current_time(olsr, &data.RX_time);
  update_time(&data.RX_time,(olsr_32_t)olsr->qual_cnf->duplicate_hold_time);

  //struct olsrv2
  OLSR_InsertList(&olsr->rcv_msg_set[olsr_hashing(olsr,&orig_addr)].list, &data, sizeof(OLSR_RCV_MSG_TUPLE));
}

void delete_rcv_msg_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  int hash_index;
  get_current_time(olsr, &time);

   for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
   {
       if(OLSR_DeleteListHandler((void*)olsr,&olsr->rcv_msg_set[hash_index].list, (void* )&time,
                 &delete_rcv_msg_set_for_timeout_handler) == OLSR_TRUE)
       {
       olsr->change_rcv_msg_set = OLSR_TRUE;
       }
   }
}


olsr_bool delete_rcv_msg_set_for_timeout_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_RCV_MSG_TUPLE *data = NULL;
  //WIN FIX: Changed the variable name start
  olsr_time_t *todelete = NULL;

  data = (OLSR_RCV_MSG_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->RX_time, *todelete) < 0);
  //WIN FIX: Changed the variable name end
}


OLSR_LIST *
search_rcv_msg_set(struct olsrv2 *olsr,
           union olsr_ip_addr orig_addr,
           olsr_u16_t seq_number,
           olsr_u8_t type)
{
  OLSR_LIST *result = NULL;
  //WIN FIX: explicit typecast required
  unsigned char *search = (unsigned char *)olsr_malloc(sizeof(union olsr_ip_addr)+sizeof(olsr_u16_t)+sizeof(olsr_u8_t), __FUNCTION__);

  memcpy(search, &orig_addr, sizeof(union olsr_ip_addr));
  search += sizeof(union olsr_ip_addr);
  memcpy(search, &seq_number, sizeof(olsr_u16_t));
  search += sizeof(olsr_u16_t);
  memcpy(search, &type, sizeof(olsr_u8_t));

  search -= sizeof(olsr_u16_t);
  search -= sizeof(union olsr_ip_addr);

  //struct olsrv2
  result = OLSR_SearchList((void*)olsr,&olsr->rcv_msg_set[olsr_hashing(olsr,&orig_addr)].list,
               (void* )search, &search_rcv_msg_set_handler);

  free(search);
  return result;
}

//WIN FIX: changed type from void* to char*
olsr_bool search_rcv_msg_set_handler(void* olsr, void *arg_a, void *arg_vb)
{
  OLSR_RCV_MSG_TUPLE *data = NULL;
  union olsr_ip_addr *orig_addr = NULL;
  olsr_u16_t *seq_number = NULL;
  olsr_u8_t *type = NULL;

  //WIN FIX: changed type from void* to char*
  char *arg_b = (char *)arg_vb;

  data = (OLSR_RCV_MSG_TUPLE *)arg_a;
  orig_addr = (union olsr_ip_addr *)arg_b;
  arg_b += sizeof(union olsr_ip_addr);
  seq_number = (olsr_u16_t *)arg_b;
  arg_b += sizeof(olsr_u16_t);
  type = (olsr_u8_t *)arg_b;

  arg_b -= sizeof(olsr_u16_t);
  arg_b -= sizeof(union olsr_ip_addr);
  //WIN FIX: explicit typecast required
  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr, &data->RX_addr, orig_addr)
      && data->RX_seq_number == *seq_number
      && data->RX_type == *type);
}


void print_rcv_msg_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_RCV_MSG_TUPLE *data = NULL;
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;
  int i;

  if(olsr_cnf->debug_level < 2)
    return;
  //struct olsrv2
  olsr_printf("--- Received Message Set ---\n");
  for(i=0; i<HASHSIZE; i++)
  {
      tmp = olsr->rcv_msg_set[i].list.head;

      if(tmp == NULL){

      }else{
      if(olsr_cnf->ip_version == AF_INET){
          char str[INET_ADDRSTRLEN];

          olsr_printf("%-16s %-12s %-12s\n", "RX_addr", "RX_seq_number", "RX_time");
          while(tmp != NULL){
          char time[30];


          data = (OLSR_RCV_MSG_TUPLE *)tmp->data;
          //WIN FIX: Need to resolve this
          //inet_ntop(AF_INET, &data->RX_addr.v4, str, sizeof(str));
          ConvertIpv4AddressToString(data->RX_addr.v4, str);

          qualnet_print_clock_in_second(data->RX_time, time);
          olsr_printf("%-16s %-12d %s [sec]\n", str, data->RX_seq_number, time);

          tmp = tmp->next;
          }

      }

      else if(olsr_cnf->ip_version == AF_INET6){
          char str[INET6_ADDRSTRLEN];

          olsr_printf("%-46s %-12s %-12s\n", "RX_addr", "RX_seq_number", "RX_time");
          while(tmp != NULL){
          char time[30];


          data = (OLSR_RCV_MSG_TUPLE *)tmp->data;
          //WIN FIX: Need to resolve this
          //inet_ntop(AF_INET6, data->RX_addr.v6.s6_addr, str, sizeof(str));
          ConvertIpv6AddressToString(&data->RX_addr.v6, str, OLSR_FALSE);

          qualnet_print_clock_in_second(data->RX_time, time);
          olsr_printf("%-46s %-12d %s [sec]\n", str, data->RX_seq_number, time);

          tmp = tmp->next;
          }

      }

      else{
          olsr_error("Un known ip_version");
          assert(OLSR_FALSE);
      }
      }
  }
  olsr_printf("----------------------------\n");
}
}
