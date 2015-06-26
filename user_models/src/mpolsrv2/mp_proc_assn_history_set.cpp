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
#include "mp_olsr_protocol.h"
#include "mp_proc_assn_history_set.h"
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

#define OLSRv2_ASSN_CYCLE 60000

/* static function prototypes */
static
void insert_assn_history_set(struct olsrv2 *,
                 union olsr_ip_addr *,
                 olsr_u16_t);

static
OLSR_LIST *search_assn_history_set(struct olsrv2 *,
                   union olsr_ip_addr *);
static
void delete_assn_history_set(struct olsrv2 *,
                 union olsr_ip_addr *);
static
olsr_bool delete_assn_history_set_handler(void* olsr, void *arg_a, void *arg_b);
static
olsr_bool delete_assn_history_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool search_assn_history_set_handler(void*, void *, void *);
static
olsr_bool search_all_assn_history_set(struct olsrv2 *olsr,
                      const union olsr_ip_addr *,
                      olsr_u16_t );


/* function implimentations */
void init_assn_history_set(struct olsrv2 *olsr)
{

  olsr->change_assn_history_set = OLSR_FALSE;
  OLSR_InitList(&olsr->assn_history_set);
}

void insert_assn_history_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *adv_neighbor_addr,
                 olsr_u16_t ASSN)
{
  OLSR_LIST* result = NULL;
  OLSR_ASSN_HISTORY_TUPLE *tmpData = NULL;


  result = search_assn_history_set(olsr,
                   adv_neighbor_addr);

  if(result){
    assert(result->numEntry == 1);
    tmpData = (OLSR_ASSN_HISTORY_TUPLE *)result->head->data;
    OLSR_DeleteList_Search(result);

    if(tmpData->AS_seq ==  ASSN){
      return;
    }else{
      delete_assn_history_set(olsr, adv_neighbor_addr);
    }
  }

  OLSR_ASSN_HISTORY_TUPLE data;

  data.AS_Address = *adv_neighbor_addr;
  data.AS_seq = ASSN;

  get_current_time(olsr, &data.AS_time);
  update_time(&data.AS_time, (olsr_32_t)olsr->qual_cnf->duplicate_hold_time);

  OLSR_InsertList(&olsr->assn_history_set, &data, sizeof(OLSR_ASSN_HISTORY_TUPLE));

}

void delete_assn_history_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  get_current_time(olsr, &time);

  OLSR_DeleteListHandler((void*)olsr,&olsr->assn_history_set, (void* )&time,
             &delete_assn_history_set_for_timeout_handler);
  olsr->change_assn_history_set = OLSR_TRUE;

}

olsr_bool delete_assn_history_set_for_timeout_handler(void* olsr,
                              void *arg_a, void *arg_b)
{
  OLSR_ASSN_HISTORY_TUPLE *data = NULL;
  olsr_time_t *todelete = NULL;

  data = (OLSR_ASSN_HISTORY_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->AS_time, *todelete) < 0);
}


olsr_bool search_all_assn_history_set(struct olsrv2 *olsr,
                      const union olsr_ip_addr *originator_addr,
                      olsr_u16_t ASSN)
{

  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ASSN_HISTORY_TUPLE* data = NULL;


  tmp = olsr->assn_history_set.head;

  while(tmp){
    data = (OLSR_ASSN_HISTORY_TUPLE* )tmp->data;
    if(equal_ip_addr(olsr, &data->AS_Address, originator_addr)             ){

      if((data->AS_seq > ASSN &&
      data->AS_seq - ASSN < OLSRv2_ASSN_CYCLE) ||
     (data->AS_seq < ASSN &&
      ASSN - data->AS_seq > OLSRv2_ASSN_CYCLE)
     ){
    //ignore this message.
    return OLSR_TRUE;
      }

    }

    tmp = tmp->next;
  }

  return OLSR_FALSE;

}


olsr_bool proc_assn_history_set(struct olsrv2 *olsr,
                union olsr_ip_addr *originator_addr,
                olsr_u16_t ASSN)
{

  if(search_all_assn_history_set(olsr, originator_addr, ASSN)){
    //10.2
    return OLSR_TRUE;

  }else{
    //10.3
    insert_assn_history_set(olsr, originator_addr, ASSN);
    return OLSR_FALSE;
  }

}

OLSR_LIST *
search_assn_history_set(struct olsrv2 *olsr,
            union olsr_ip_addr *originator_addr)
{
  OLSR_LIST *result = NULL;

  return result = OLSR_SearchList((void*)olsr,&olsr->assn_history_set,
                  (void* )originator_addr,
                  &search_assn_history_set_handler);

}

olsr_bool search_assn_history_set_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_ASSN_HISTORY_TUPLE *data = NULL;
  union olsr_ip_addr *originator_addr = NULL;

  data = (OLSR_ASSN_HISTORY_TUPLE *)arg_a;
  originator_addr = (union olsr_ip_addr *)arg_b;


  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->AS_Address,
                   originator_addr));
}

void delete_assn_history_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *originator_addr)
{
  OLSR_DeleteListHandler((void*)olsr,&olsr->assn_history_set,
             (void* )originator_addr,
             &delete_assn_history_set_handler);

}

olsr_bool delete_assn_history_set_handler(void* olsr,
                      void *arg_a, void *arg_b)
{
  OLSR_ASSN_HISTORY_TUPLE *data = NULL;
  union olsr_ip_addr *originator_addr = NULL;

  data = (OLSR_ASSN_HISTORY_TUPLE *)arg_a;
  originator_addr = (union olsr_ip_addr *)arg_b;


  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->AS_Address,
                   originator_addr));
}

void print_assn_history_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ASSN_HISTORY_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp = olsr->assn_history_set.head;

  if(tmp == NULL){
    olsr_printf("--- Assn_History Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("--------------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN];

      olsr_printf("--------------------------- Assn_History Set ----------------------------\n");
      olsr_printf("%-17s %-12s %-20s\n",
         "AS_Address", "AS_seq", "AS_time");
      olsr_printf("---------------------------------------------------------------------\n");
      while(tmp != NULL){
    char time[30];

    data = (OLSR_ASSN_HISTORY_TUPLE *)tmp->data;

    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->AS_Address.v4, str1, sizeof(str1));
    ConvertIpv4AddressToString(data->AS_Address.v4, str1);

    qualnet_print_clock_in_second(data->AS_time, time);
    olsr_printf("%-17s %-12d %s [sec]\n",
           str1, data->AS_seq, time);
    tmp = tmp->next;
      }

      olsr_printf("---------------------------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str1[INET6_ADDRSTRLEN];

      olsr_printf("-------------------------------------------------------- Assn_History Set ---------------------------------------------------------\n");
      olsr_printf("%-46s %-12s %-20s\n",
        "AS_Address", "AS_seq", "AS_time");
      olsr_printf("-------------------------------------------------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    char time[30];

    data = (OLSR_ASSN_HISTORY_TUPLE *)tmp->data;

    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET6, data->data->AS_Address.v6.s6_addr, str1, sizeof(str1));
    ConvertIpv6AddressToString(&data->AS_Address.v6, str1, OLSR_FALSE);

    qualnet_print_clock_in_second(data->AS_time, time);
    olsr_printf("%-46s %-12d %s [sec]\n",
           str1, data->AS_seq, time);
    tmp = tmp->next;
      }

      olsr_printf("-------------------------------------------------------------------------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}
}
