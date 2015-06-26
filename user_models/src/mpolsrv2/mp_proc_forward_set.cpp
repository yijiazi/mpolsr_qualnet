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
#include <assert.h>
#include <string.h>
//WIN FIX
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif
#include "mp_olsr_debug.h"
#include "mp_olsr_conf.h"
#include "mp_def.h"
#include "mp_proc_forward_set.h"
#include "mp_proc_relay_set.h"
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{


/* static function prototypes */
static
void insert_forward_set(struct olsrv2 *, union olsr_ip_addr *, olsr_u16_t);
static
OLSR_LIST *search_forward_set(struct olsrv2 *, union olsr_ip_addr *, olsr_u16_t);
static
olsr_bool delete_forward_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool search_forward_set_handler(void *, void *, void *);


/* function implimentations */
void init_forward_set(struct olsrv2 *olsr)
{
  olsr->change_forward_set = OLSR_FALSE;
  OLSR_InitHashList(olsr->forward_set);
}

olsr_bool proc_forward_set(struct olsrv2 *olsr,
               union olsr_ip_addr *org_addr,
               union olsr_ip_addr *src_addr,
               olsr_u16_t seq_number)
{
  OLSR_LIST *retList = NULL;


  retList = search_forward_set(olsr, org_addr, seq_number);

  //4.4.2.3
  if(retList == NULL){

    int retNum = check_relay_set_for_match_num_entry(olsr,
                             src_addr);

    if(retNum){
      assert(retNum == 1);

      //4.4.2.3.1
      insert_forward_set(olsr, org_addr, seq_number);
      olsr->change_forward_set = OLSR_TRUE;
      //4.6.2.3
      //4.6.2.4

      return OLSR_TRUE;
    }

    return OLSR_FALSE;
  }else{

    OLSR_DeleteList_Search(retList);
    return OLSR_FALSE;
  }
}

void insert_forward_set(struct olsrv2 *olsr,
            union olsr_ip_addr *orig_addr,
            const olsr_u16_t seq_number)
{
  OLSR_FORWARD_TUPLE data;

  data.F_addr = *orig_addr;
  data.F_seq_number = seq_number;
  get_current_time(olsr, &data.F_time);
  update_time(&data.F_time,(olsr_32_t)olsr->qual_cnf->duplicate_hold_time);
  //  data.F_time = current_time();
  //  data.F_time.tv_sec += olsr->qual_cnf->duplicate_hold_time;


  OLSR_InsertList(&olsr->forward_set[olsr_hashing(olsr,orig_addr)].list, &data, sizeof(OLSR_FORWARD_TUPLE));
}

void delete_forward_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  int i;
  get_current_time(olsr, &time);

  for(i = 0; i < HASHSIZE; i++)
  {
    if(OLSR_DeleteListHandler((void*)olsr,&olsr->forward_set[i].list,
                      (void* )&time,
                  &delete_forward_set_for_timeout_handler) == OLSR_TRUE)
    {
    olsr->change_forward_set = OLSR_TRUE;
    }
  }
}

olsr_bool delete_forward_set_for_timeout_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_FORWARD_TUPLE *data = NULL;
  olsr_time_t todelete = 0;

  data = (OLSR_FORWARD_TUPLE *)arg_a;
//Solaris Crash Fix
  //todelete = (olsr_time_t *)arg_b;
  memcpy(&todelete, arg_b, sizeof(olsr_time_t));

  return (olsr_bool)(olsr_cmp_time(data->F_time, todelete) < 0);
}

OLSR_LIST *
search_forward_set(struct olsrv2 *olsr,
           union olsr_ip_addr *orig_addr ,
           olsr_u16_t seq_number)
{
  OLSR_LIST *result = NULL;
  OLSR_FORWARD_TUPLE search;


  olsr_ip_copy(olsr, &search.F_addr, orig_addr);
  search.F_seq_number = seq_number;

  result = OLSR_SearchList((void*)olsr,&olsr->forward_set[olsr_hashing(olsr,orig_addr)].list,
               (void *)&search,
               &search_forward_set_handler);

  return result;
}

olsr_bool search_forward_set_handler(void *olsr, void *arg_a, void *arg_vb)
{
  OLSR_FORWARD_TUPLE *data = NULL;
  union olsr_ip_addr *orig_addr = NULL;
  olsr_u16_t *seq_number = NULL;
  char* arg_b = (char* )arg_vb;

  data = (OLSR_FORWARD_TUPLE *)arg_a;
  orig_addr = (union olsr_ip_addr *)arg_b;
  arg_b +=  sizeof(union olsr_ip_addr);
  seq_number = (olsr_u16_t *)arg_b;
  arg_b -= sizeof(union olsr_ip_addr);

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->F_addr, orig_addr) &&
             data->F_seq_number == *seq_number);
}

void print_forward_set(struct olsrv2 *olsr)
{
  int hash_index;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_FORWARD_TUPLE *data = NULL;
  olsr_bool put_head = OLSR_FALSE;

  if(olsr->olsr_cnf->debug_level < 4)
    return;
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++){
    entry = olsr->forward_set[hash_index].list.head;
    while(entry){
      if(put_head == OLSR_FALSE){
    olsr_printf("-------------------------------- Foward Set -----------------------------------\n");
    if(olsr->olsr_cnf->ip_version == AF_INET)
      olsr_printf("%-25s %-25s %-25s\n",
         "F_addr", "F_sequence_number", "F_time");
    else
      olsr_printf("%-46s %-25s %-25s\n",
         "F_addr", "F_sequence_number", "F_time");
    put_head = OLSR_TRUE;
      }
      data = (OLSR_FORWARD_TUPLE *)entry->data;
      if(olsr->olsr_cnf->ip_version == AF_INET){
    char str1[INET_ADDRSTRLEN];
    //yowada
    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->F_addr.v4, str1, sizeof(str1));
    ConvertIpv4AddressToString(data->F_addr.v4, str1);
    char time[30];
    qualnet_print_clock_in_second(data->F_time, time);
    olsr_printf("%-25s %-25d %-25s\n", str1, data->F_seq_number, time);
      }else{
    char str1[INET6_ADDRSTRLEN];

    //inet_ntop(AF_INET6, data->F_addr.v6.s6_addr, str1, sizeof(str1));
    ConvertIpv6AddressToString(&data->F_addr.v6, str1, OLSR_FALSE);
    char time[30];
    qualnet_print_clock_in_second(data->F_time, time);
    olsr_printf("%-46s %-25d %-25s\n", str1, data->F_seq_number, time);
      }
      entry = entry->next;
    }
  } // for

  if(put_head == OLSR_FALSE){
    olsr_printf("---------------------------------- Forward Set -----------------------------\n");
    olsr_printf("\t\tno entry.\n");
  }
  olsr_printf("\n");
}
}
