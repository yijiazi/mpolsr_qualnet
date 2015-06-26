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
#include "mp_proc_routing_set.h"
#include "mp_proc_attach_network_set.h"
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{


/* static function prototypes */
static
void insert_attached_set(struct olsrv2 *,
             const union olsr_ip_addr *,
             olsr_u8_t,
             const union olsr_ip_addr *,
             olsr_u16_t);

static
OLSR_LIST *search_attached_set(struct olsrv2 *,
                   const union olsr_ip_addr *,
                   olsr_u8_t,
                   const union olsr_ip_addr *);
static
olsr_bool delete_attached_set_for_timeout_handler(void*, void *, void *);

static
olsr_bool search_attached_set_handler(void*, void *, void *);

static
olsr_bool search_attached_and_routing_handler(void* olsr,
                          void *arg_a, void *arg_b);

/* function implimentations */
void init_attached_set(struct olsrv2 *olsr)
{
  olsr->change_attached_set = OLSR_FALSE;
  OLSR_InitList(&olsr->attached_set);
}

void proc_attached_set(struct olsrv2 *olsr,
               const union olsr_ip_addr *adv_neighbor_addr,
               olsr_u8_t prefix_length,
               const union olsr_ip_addr *orig_addr,
               olsr_u16_t ASSN)
{
  OLSR_ATTACHED_TUPLE *data = NULL;

  OLSR_LIST *retList = NULL;

  //10.4.1
  retList = search_attached_set(olsr,
                adv_neighbor_addr,
                prefix_length,
                orig_addr);

  //10.4.1.1
  if(retList != NULL){
    assert(retList->numEntry == 1);

    data = (OLSR_ATTACHED_TUPLE *)retList->head->data;
    get_current_time(olsr, &data->AN_time);


    update_time(&data->AN_time,(olsr_32_t)olsr->qual_cnf->duplicate_hold_time);
    data->AN_seq = ASSN;


    OLSR_DeleteList_Search(retList);
  }

  //10.4.1.2
  else{
    insert_attached_set(olsr,
            adv_neighbor_addr,
            prefix_length,
            orig_addr,
            ASSN);
    olsr->change_attached_set = OLSR_TRUE;
  }


}



void insert_attached_set(struct olsrv2 *olsr,
             const union olsr_ip_addr *adv_neighbor_addr,
             olsr_u8_t prefix_length,
             const union olsr_ip_addr *orig_addr,
             olsr_u16_t ASSN)
{
  OLSR_ATTACHED_TUPLE data;

  data.AN_net_addr = *adv_neighbor_addr;
  data.AN_prefix_length = prefix_length;
  data.AN_gw_addr = *orig_addr;
  data.AN_seq = ASSN;

  get_current_time(olsr, &data.AN_time);
  update_time(&data.AN_time,(olsr_32_t)olsr->qual_cnf->duplicate_hold_time);

  OLSR_InsertList(&olsr->attached_set, &data, sizeof(OLSR_ATTACHED_TUPLE));
}

void delete_attached_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  get_current_time(olsr, &time);

  olsr->change_attached_set =
    OLSR_DeleteListHandler((void*)olsr,&olsr->attached_set, (void* )&time,
               &delete_attached_set_for_timeout_handler);

}

olsr_bool delete_attached_set_for_timeout_handler(void* olsr,
                          void *arg_a, void *arg_b)
{
  OLSR_ATTACHED_TUPLE *data = NULL;
  olsr_time_t *todelete = NULL;

  data = (OLSR_ATTACHED_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->AN_time, *todelete) < 0);
}


OLSR_LIST *
search_attached_set(struct olsrv2 *olsr,
            const union olsr_ip_addr *adv_neighbor_addr,
            olsr_u8_t prefix_length,
            const union olsr_ip_addr *orig_addr)
{
  OLSR_LIST *result = NULL;
  OLSR_ATTACHED_TUPLE search;

  olsr_ip_copy(olsr, &search.AN_net_addr, adv_neighbor_addr);
  search.AN_prefix_length = prefix_length;
  olsr_ip_copy(olsr, &search.AN_gw_addr, orig_addr);

  result = OLSR_SearchList((void*)olsr,&olsr->attached_set,
               (void* )&search,
               &search_attached_set_handler);

  return result;
}

olsr_bool search_attached_set_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_ATTACHED_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_ATTACHED_TUPLE *)arg_a;
  param = (OLSR_ATTACHED_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr, &data->AN_net_addr,
                   &param->AN_net_addr) &&
             equal_ip_addr((struct olsrv2* )olsr, &data->AN_gw_addr,
                   &param->AN_gw_addr) &&
             (data->AN_prefix_length == param->AN_prefix_length));
}

void add_attached_network_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY* tmp = NULL;
  OLSR_ATTACHED_TUPLE *data = NULL;
  OLSR_LIST *result = NULL;

  tmp = olsr->attached_set.head;

  while(tmp){
    data = (OLSR_ATTACHED_TUPLE *)tmp->data;

    result = OLSR_SearchList((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,&data->AN_net_addr)].list,
                 (void* )&data->AN_net_addr,
                 &search_attached_and_routing_handler);
    if(result){

      OLSR_LIST *gw_result = NULL;

      gw_result = OLSR_SearchList((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,&data->AN_gw_addr)].list,
                  (void* )&data->AN_gw_addr,
                  &search_attached_and_routing_handler);

      if(gw_result){
    OLSR_ROUTING_TUPLE* base_data = NULL, *gw_data = NULL;
    gw_data = (OLSR_ROUTING_TUPLE* )gw_result->head->data;
    base_data = (OLSR_ROUTING_TUPLE* )result->head->data;

    if(base_data->R_dist > gw_data->R_dist){

      OLSR_DeleteListHandler((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,&data->AN_net_addr)].list,
                 (void* )&data->AN_net_addr,
                 &search_attached_and_routing_handler);

      insert_routing_set(olsr,
                 &data->AN_net_addr,
                 &gw_data->R_next_iface_addr,
                 data->AN_prefix_length,
                 gw_data->R_dist,
                 &gw_data->R_iface_addr);
    }
    OLSR_DeleteList_Search(gw_result);
      }

      OLSR_DeleteList_Search(result);
      //XXX
    }else{

      OLSR_LIST *gw_result = NULL;

      gw_result = OLSR_SearchList((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,&data->AN_gw_addr)].list,
                  (void* )&data->AN_gw_addr,
                  &search_attached_and_routing_handler);

      if(gw_result){
    OLSR_ROUTING_TUPLE* gw_data = NULL;
    gw_data = (OLSR_ROUTING_TUPLE* )gw_result->head->data;

    insert_routing_set(olsr,
               &data->AN_net_addr,
               &gw_data->R_next_iface_addr,
               data->AN_prefix_length,
               gw_data->R_dist,
               &gw_data->R_iface_addr);
    OLSR_DeleteList_Search(gw_result);
      }

    }

    tmp = tmp->next;
  }//while



}

olsr_bool search_attached_and_routing_handler(void* olsr,
                          void *arg_a, void *arg_b)
{
  OLSR_ROUTING_TUPLE *data = NULL;
  union olsr_ip_addr *AN_net_addr = NULL;

  data = (OLSR_ROUTING_TUPLE *)arg_a;
  AN_net_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->R_dest_iface_addr,
                   AN_net_addr));
}




void print_attached_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ATTACHED_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp = olsr->attached_set.head;

  if(tmp == NULL){
    olsr_printf("--- Attached Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("--------------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];

      olsr_printf("--------------------------- Attached Set ----------------------------\n");
      olsr_printf("%-17s %-17s %-17s %-12s %-20s\n",
         "AN_net_addr", "AN_prefix_length", "AN_gw_addr", "AN_seq", "AN_time");
      olsr_printf("---------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_ATTACHED_TUPLE *)tmp->data;

    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->AN_net_addr.v4, str1, sizeof(str1));
    //inet_ntop(AF_INET, &data->AN_gw_addr.v4, str2, sizeof(str2));
    ConvertIpv4AddressToString(data->AN_net_addr.v4, str1);
    ConvertIpv4AddressToString(data->AN_gw_addr.v4, str2);

    char time[30];
    qualnet_print_clock_in_second(data->AN_time, time);
    olsr_printf("%-17s %-17d %-17s %-12d %s\n",
           str1, data->AN_prefix_length, str2, data->AN_seq, time);
    tmp = tmp->next;
      }

      olsr_printf("---------------------------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];

      olsr_printf("-------------------------------------------------------- Attached Set ---------------------------------------------------------\n");
      olsr_printf("%-46s %-17s %-46s %-12s %-20s\n",
        "AN_net_addr", "AN_prefix_length", "AN_gw_addr", "AN_seq", "AN_time");
      olsr_printf("-------------------------------------------------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_ATTACHED_TUPLE *)tmp->data;

    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET6, data->AN_net_addr.v6.s6_addr, str1, sizeof(str1));
    //inet_ntop(AF_INET6, data->AN_gw_addr.v6.s6_addr, str2, sizeof(str2));
    ConvertIpv6AddressToString(&data->AN_net_addr.v6, str1, OLSR_FALSE);
    ConvertIpv6AddressToString(&data->AN_gw_addr.v6, str2, OLSR_FALSE);

    char time[30];
    qualnet_print_clock_in_second(data->AN_time, time);
    olsr_printf("%-46s %-17d %-46s %-12d %s [sec]\n",
           str1, data->AN_prefix_length, str2, data->AN_seq, time);
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
