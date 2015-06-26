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
#include "mp_proc_topology_set.h"
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"

#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

/* static function prototypes */
static
void insert_topology_set(struct olsrv2 *,
             const union olsr_ip_addr *, union olsr_ip_addr *, olsr_u16_t);
static
void delete_topology_set_for_same_entry(struct olsrv2 *,
                    const union olsr_ip_addr *, olsr_u16_t);
static
OLSR_LIST *search_topology_set(struct olsrv2 *,
                   const union olsr_ip_addr *, union olsr_ip_addr *);
static
olsr_bool delete_topology_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool delete_topology_set_for_same_entry_handler(void*, void *, void *);
static
olsr_bool search_topology_set_handler(void*, void *, void *);

static olsr_bool lookup_topology_set_handler(void*, void *,void *);


static
olsr_bool search_topology_set_handler_for_last(void* olsr, void *arg_a, void *arg_b);

void print_topology_set_head(struct olsrv2 *olsr);
/* function implimentations */
void init_topology_set(struct olsrv2 *olsr)
{
  olsr->change_topology_set = OLSR_FALSE;
  OLSR_InitHashList(olsr->topology_set);
}

void proc_topology_set(struct olsrv2 *olsr,
               const union olsr_ip_addr *adv_neighbor_addr,
               union olsr_ip_addr *orig_addr,
               olsr_u16_t ASSN, olsr_bool frag)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL;

  OLSR_LIST *retList = NULL;

  //10.2

  //10.3 ???
  if(!frag) //no frag
    delete_topology_set_for_same_entry(olsr,
                       orig_addr, ASSN);

    retList = search_topology_set(olsr,
                adv_neighbor_addr, orig_addr);

  //10.2.1.1
  if(retList != NULL){
    assert(retList->numEntry == 1);

    data = (OLSR_TOPOLOGY_TUPLE *)retList->head->data;
    get_current_time(olsr, &data->T_time);
    update_time(&data->T_time,(olsr_32_t)olsr->qual_cnf->topology_hold_time);

    //Note that necessarily
    if(data->T_seq != ASSN)
    {
        olsr_printf("data->T_seq != ASSN\n");
    }

    OLSR_DeleteList_Search(retList);
  }

  //10.2.1.2
  else{
    if(!frag)
      insert_topology_set(olsr,
              adv_neighbor_addr, orig_addr, ASSN);
    olsr->change_topology_set = OLSR_TRUE;
  }

}

void insert_topology_set(struct olsrv2 *olsr,
             const union olsr_ip_addr *adv_neighbor_addr,
             union olsr_ip_addr *orig_addr,
             olsr_u16_t ASSN)
{
  OLSR_TOPOLOGY_TUPLE data;
//Fix for Solaris
  //data.T_dest_iface_addr = *adv_neighbor_addr;
  //data.T_last_iface_addr = *orig_addr;
  olsr_ip_copy(olsr, &data.T_dest_iface_addr, adv_neighbor_addr);
  olsr_ip_copy(olsr, &data.T_last_iface_addr, orig_addr);
  data.T_seq = ASSN;

  get_current_time(olsr, &data.T_time);
  update_time(&data.T_time,(olsr_32_t)olsr->qual_cnf->topology_hold_time);

  OLSR_InsertList(&olsr->topology_set[olsr_hashing(olsr,orig_addr)].list,
          &data,
          sizeof(OLSR_TOPOLOGY_TUPLE));
}

/*
  OLSR_InsertList_Sort(&olsr->topology_set[olsr_hashing(olsr,orig_addr)].list,
  &data,
  sizeof(OLSR_TOPOLOGY_TUPLE),


  sort_topology_set_handler);

  }

  olsr_bool sort_topology_set_handler(void* arg_a, void* arg_b)
  {
  OLSR_TOPOLOGY_TUPLE* data, *insert;

  data = (OLSR_TOPOLOGY_TUPLE* )arg_a;
  insert = (OLSR_TOPOLOGY_TUPLE* )arg_b;


  if(equal_ip_addr(&data->T_last_iface_addr, &insert->T_last_iface_addr))
    {
      if(cmp_ip_addr(&data->T_dest_iface_addr, &insert->T_dest_iface_addr) > 0)
    {
      return OLSR_TRUE;
    }
      else
    {
      return OLSR_FALSE;
    }
    }
  else if(cmp_ip_addr(&data->T_last_iface_addr, &insert->T_last_iface_addr) > 0)
    {
      return OLSR_TRUE;
    }

  return OLSR_FALSE;
}

*/


void delete_topology_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  int hash_index;
  olsr_bool deleted_flag = OLSR_FALSE;

  get_current_time(olsr, &time);

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      if(OLSR_DeleteListHandler((void*)olsr,&olsr->topology_set[hash_index].list, (void* )&time,
                &delete_topology_set_for_timeout_handler) == OLSR_TRUE)
    deleted_flag = OLSR_TRUE;
    }
  if(deleted_flag)
    {
      olsr->change_topology_set = OLSR_TRUE;
    }
}

olsr_bool delete_topology_set_for_timeout_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL;
  olsr_time_t *todelete = NULL;

  data = (OLSR_TOPOLOGY_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->T_time, *todelete) < 0);
}
void delete_topology_set_for_same_entry(struct olsrv2 *olsr,
                    const union olsr_ip_addr *orig_addr,
                    olsr_u16_t ASSN)
{
  OLSR_TOPOLOGY_TUPLE todelete;

  olsr_ip_copy(olsr, &todelete.T_last_iface_addr, orig_addr);
  todelete.T_seq = ASSN;

  olsr->change_topology_set =
    OLSR_DeleteListHandler((void*)olsr,&olsr->topology_set[olsr_hashing(olsr,orig_addr)].list,
               (void* )&todelete,
               &delete_topology_set_for_same_entry_handler);
}

olsr_bool delete_topology_set_for_same_entry_handler(void* olsr,
                             void *arg_a, void *arg_b)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_TOPOLOGY_TUPLE *)arg_a;
  param = (OLSR_TOPOLOGY_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->T_last_iface_addr,
                   &param->T_last_iface_addr) &&
             data->T_seq < param->T_seq);
}

OLSR_LIST *
search_topology_set(struct olsrv2 *olsr,
            const union olsr_ip_addr *adv_neighbor_addr,
            union olsr_ip_addr *orig_addr)
{
  OLSR_LIST *result = NULL;
  OLSR_TOPOLOGY_TUPLE search;

  olsr_ip_copy(olsr, &search.T_dest_iface_addr, adv_neighbor_addr);
  olsr_ip_copy(olsr, &search.T_last_iface_addr, orig_addr);

  result = OLSR_SearchList((void*)olsr,&olsr->topology_set[olsr_hashing(olsr,orig_addr)].list,
               (void* )&search,
               &search_topology_set_handler);

  return result;
}


olsr_bool search_topology_set_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_TOPOLOGY_TUPLE *)arg_a;
  param = (OLSR_TOPOLOGY_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->T_dest_iface_addr,
                   &param->T_dest_iface_addr) &&
             equal_ip_addr((struct olsrv2* )olsr,
                   &data->T_last_iface_addr,
                   &param->T_last_iface_addr));
}


OLSR_LIST *
search_topology_set_for_last(struct olsrv2 *olsr,
                 union olsr_ip_addr *last_addr)
{
  OLSR_LIST *result = NULL;

  result = OLSR_SearchList((void*)olsr,&olsr->topology_set[olsr_hashing(olsr,last_addr)].list,
               (void* )last_addr,
               &search_topology_set_handler_for_last);

  return result;
}

olsr_bool search_topology_set_handler_for_last(void* olsr,
                           void *arg_a, void *arg_b)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL;
  union olsr_ip_addr *last_addr = NULL;

  data = (OLSR_TOPOLOGY_TUPLE *)arg_a;
  last_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->T_last_iface_addr,
                   last_addr));
}


void print_topology_set(struct olsrv2 *olsr)
{
 int hash_index;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_TOPOLOGY_TUPLE *data = NULL;
  olsr_bool put_head = OLSR_FALSE;

  if(olsr->olsr_cnf->debug_level < 2)
    return;
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      entry = olsr->topology_set[hash_index].list.head;
      while(entry){
    if(put_head == OLSR_FALSE){
      olsr_printf("--------------------------------------- Topology Set -------------------------\n");
      if(olsr->olsr_cnf->ip_version == AF_INET)
        olsr_printf("%-25s %-25s %-20s %-25s\n",
           "T_dest_iface_addr", "T_last_iface_addr", "T_seq", "T_time");
      else
        olsr_printf("%-46s %-46s %-20s %-46s\n",
           "T_dest_iface_addr", "T_last_iface_addr", "T_seq", "T_time");
      put_head = OLSR_TRUE;
    }

    data = (OLSR_TOPOLOGY_TUPLE *)entry->data;
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];
      char time[30];

      //WIN FIX: Need to resolve this
      //inet_ntop(AF_INET, &data->T_dest_iface_addr.v4, str1, sizeof(str1));
      //inet_ntop(AF_INET, &data->T_last_iface_addr.v4, str2, sizeof(str2));
      ConvertIpv4AddressToString(data->T_dest_iface_addr.v4, str1);
      ConvertIpv4AddressToString(data->T_last_iface_addr.v4, str2);

      qualnet_print_clock_in_second(data->T_time, time);
      olsr_printf("%-25s %-25s %-20d %-25s\n", str1, str2, data->T_seq, time);
    }else{
       char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];
       char time[30];

       //WIN FIX: Need to resolve this
       //inet_ntop(AF_INET6, data->T_dest_iface_addr.v6.s6_addr, str1, sizeof(str1));
       //inet_ntop(AF_INET6, data->T_last_iface_addr.v6.s6_addr, str2, sizeof(str2));
       ConvertIpv6AddressToString(&data->T_dest_iface_addr.v6, str1, OLSR_FALSE);
       ConvertIpv6AddressToString(&data->T_last_iface_addr.v6, str2, OLSR_FALSE);

       qualnet_print_clock_in_second(data->T_time, time);
       olsr_printf("%-46s %-46s %-20d %s [sec]\n", str1, str2, data->T_seq, time);
    }//if
    entry = entry->next;
      }//while

    }//for

  if(put_head == OLSR_FALSE){
    olsr_printf("------------------------------ Topology Set ----------------------------\n");
    olsr_printf("                                no entry.\n");
  }
  olsr_printf("\n");

}


OLSR_LIST *lookup_topology_set(struct olsrv2 *olsr,
                   union olsr_ip_addr *T_last_addr )
{
  OLSR_LIST *result = NULL;

  result = OLSR_SearchList((void*)olsr,&olsr->topology_set[olsr_hashing(olsr,T_last_addr)].list,
               &T_last_addr,
               &lookup_topology_set_handler);

  return result;
}

olsr_bool lookup_topology_set_handler(void* olsr, void *arg_a,void *arg_b)
{
  OLSR_TOPOLOGY_TUPLE *data = NULL;
  union olsr_ip_addr *T_last_addr = NULL;

  data = (OLSR_TOPOLOGY_TUPLE *)arg_a;
  T_last_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->T_last_iface_addr,
                   T_last_addr));
}
}
