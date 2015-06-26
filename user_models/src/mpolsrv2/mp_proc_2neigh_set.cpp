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
#include "mp_proc_2neigh_set.h"

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
#include "mp_olsr_util.h"

#include "mp_proc_link_set.h"

#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

/* static function prototypes */
static
void insert_2neigh_set(struct olsrv2 *,
               const union olsr_ip_addr *,
               const union olsr_ip_addr *,
               const union olsr_ip_addr *,
               double);

static
OLSR_LIST *search_2neigh_set(struct olsrv2 *,
                 const union olsr_ip_addr *,
                 union olsr_ip_addr *,
                 const union olsr_ip_addr *);
olsr_bool search_2neigh_set_for_exist(struct olsrv2 *,
                 const union olsr_ip_addr *,
                 union olsr_ip_addr *,
                 const union olsr_ip_addr *);

static
olsr_bool delete_2neigh_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool delete_2neigh_set_for_neighbor_handler(void *, void *, void *);
static
olsr_bool search_2neigh_set_handler(void *, void *, void *);
static
olsr_bool search_2neigh_set_for_mpr_n_handler(void *, void *, void *);
static
olsr_bool search_2neigh_set_for_mpr_n2_handler(void *, void *, void *);
static
olsr_bool sort_two_neigh_set_handler(void *, void* arg_a, void* arg_b);
olsr_bool delete_2neigh_set_handler(void *, void *, void *);

/* function implimentations */
void init_2neigh_set(struct olsrv2 *olsr)
{
  olsr->change_two_neigh_set = OLSR_FALSE;
  OLSR_InitHashList(olsr->two_neigh_set);
}

void proc_2neigh_set(struct olsrv2 *olsr,
             const union olsr_ip_addr *local_iface_addr,
             union olsr_ip_addr *source_addr,
             const union olsr_ip_addr *two_nei_addr,
             olsr_u8_t link_status,
             olsr_u8_t other_neigh,
             double  validity_time)
{
  OLSR_2NEIGH_TUPLE *two_nei_data = NULL;
  OLSR_LINK_TUPLE *link_data = NULL;

  OLSR_LIST *retList = NULL;
  olsr_bool exist;

  olsr_time_t time;

  //8.2
  // If the Source Address is the L_local_iface_addr from a link tuple
  // included in the Link Set with L_STATUS equal to SYMMETRIC (in other
  // words: if the Source Address is a symmetric neighbor interface)
  // then the 2-hop Neighbor Set SHOULD be updated as follows:

  retList = search_link_set(olsr, source_addr);

  if(retList != NULL){
    assert(retList->numEntry == 1);
    link_data = (OLSR_LINK_TUPLE *)retList->head->data;

    OLSR_DeleteList_Search(retList);
    get_current_time(olsr, &time);
    if(get_link_status(time,
               link_data->L_SYM_time,
               link_data->L_ASYM_time,
               link_data->L_LOST_LINK_time) != SYMMETRIC){
      exist = OLSR_FALSE;

      if(DEBUG_OLSRV2)
      {
      olsr_printf("%s: (%d) the source address is not a symmetric neighbor interface.\n", __FUNCTION__, __LINE__);
      }
    }else
      exist = OLSR_TRUE;

  }else{
    exist = OLSR_FALSE;

    if(DEBUG_OLSRV2)
    {
    olsr_printf("%s: (%d) the source address don't exist in Link Set.\n", __FUNCTION__, __LINE__);
    }
  }

  //8.2.1
  if(exist){
    if(link_status == SYMMETRIC || other_neigh == SYMMETRIC){

/*  if(equal_ip_addr(olsr, (union olsr_ip_addr*)two_nei_addr,
                (union olsr_ip_addr*)local_iface_addr)){*/
    if(own_ip_addr(olsr, (union olsr_ip_addr*)two_nei_addr)){
    //8.2.1.1
    //silently discard the 2-hop neighbor address.
      }else{
    retList =
      search_2neigh_set(olsr,
                local_iface_addr,
                source_addr,
                two_nei_addr);

    //8.2.1.2
    if(retList == NULL){ //new
      insert_2neigh_set(olsr,
                local_iface_addr, source_addr,
                two_nei_addr,validity_time);
      olsr->change_two_neigh_set = OLSR_TRUE;

    }else{ //update
      assert(retList->numEntry == 1);

      two_nei_data = (OLSR_2NEIGH_TUPLE *)retList->head->data;
      get_current_time(olsr, &two_nei_data->N2_time);
      update_time(&two_nei_data->N2_time, (olsr_32_t)validity_time);

      //olsr->change_two_neigh_set = OLSR_TRUE;

      OLSR_DeleteList_Search(retList);
    }
      }
      //8.2.1.3 ??
    }else if(link_status == LOST || other_neigh == LOST) {
      //delete_2neigh_set(olsr, local_iface_addr, source_addr, two_neigh_addr);
    }else{

    if(DEBUG_OLSRV2)
    {
        olsr_printf("%s: (%d) the 2-hop neighbor address is not a symmetric 2-hop neighbor interface.\n", __FUNCTION__, __LINE__);
    }
    }
  }
}

void insert_2neigh_set(struct olsrv2 *olsr,
               const union olsr_ip_addr *local_iface_addr,
               const union olsr_ip_addr *source_addr,
               const union olsr_ip_addr *two_nei_addr,
               double validity_time)
{
  OLSR_2NEIGH_TUPLE data;

  data.N2_neighbor_iface_addr = *source_addr;
  data.N2_local_iface_addr = *local_iface_addr;
  data.N2_2hop_iface_addr = *two_nei_addr;
  get_current_time(olsr, &data.N2_time);
  update_time(&data.N2_time, (olsr_32_t)validity_time);


  OLSR_InsertList_Sort((void* )olsr,
               &olsr->two_neigh_set[olsr_hashing(olsr,&data.N2_neighbor_iface_addr)].list,
               &data,
               sizeof(OLSR_2NEIGH_TUPLE),
               sort_two_neigh_set_handler);
}


olsr_bool sort_two_neigh_set_handler(void *olsr, void* arg_a, void* arg_b)
{
  OLSR_2NEIGH_TUPLE* data, *insert;

  data = (OLSR_2NEIGH_TUPLE* )arg_a;
  insert = (OLSR_2NEIGH_TUPLE* )arg_b;

  if(equal_ip_addr((struct olsrv2 *)olsr, &data->N2_2hop_iface_addr, &insert->N2_2hop_iface_addr))
    {
      if(cmp_ip_addr((struct olsrv2* )olsr,
             &data->N2_neighbor_iface_addr,
             &insert->N2_neighbor_iface_addr) > 0)
    {
      return OLSR_TRUE;
    }
      else
    {
      return OLSR_FALSE;
    }
    }
  else if(cmp_ip_addr((struct olsrv2* )olsr,
              &data->N2_2hop_iface_addr, &insert->N2_2hop_iface_addr) > 0)
    {
      return OLSR_TRUE;
    }

  return OLSR_FALSE;
}

void delete_2neigh_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  olsr_bool deleted_flag = OLSR_FALSE;
  int hash_index;
  get_current_time(olsr, &time);

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      if(OLSR_DeleteListHandler((void*)olsr,
                &olsr->two_neigh_set[hash_index].list,
                (void* )&time,
                &delete_2neigh_set_for_timeout_handler) == OLSR_TRUE)
    deleted_flag = OLSR_TRUE;
    }

  if(deleted_flag)
    {
      olsr->change_two_neigh_set = OLSR_TRUE;
    }
}

olsr_bool delete_2neigh_set_for_timeout_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_2NEIGH_TUPLE *data = NULL;
  //WIN FIX: Changed the variable name
  olsr_time_t *todelete = NULL;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  //WIN FIX: Changed the variable name
  todelete = (olsr_time_t *)arg_b;
    //WIN FIX: explicit typecast required
  return (olsr_bool)(olsr_cmp_time(data->N2_time, *todelete) < 0);
}

void delete_2neigh_set(struct olsrv2 *olsr,
               union olsr_ip_addr *local_iface_addr,
               union olsr_ip_addr *source_addr,
               union olsr_ip_addr *two_neigh_addr) {
  OLSR_2NEIGH_TUPLE todelete;
  int hash_index;

  olsr_ip_copy(olsr, &todelete.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &todelete.N2_neighbor_iface_addr, source_addr);
  olsr_ip_copy(olsr, &todelete.N2_2hop_iface_addr, two_neigh_addr);
  hash_index = olsr_hashing(olsr,source_addr);

  if(OLSR_DeleteListHandler((void*)olsr,&olsr->two_neigh_set[hash_index].list, (void* )&todelete,
                &delete_2neigh_set_handler)) {
    olsr->change_two_neigh_set = OLSR_TRUE;
  }

}

olsr_bool delete_2neigh_set_handler(void *olsr, void *arg_a, void *arg_b) {
  OLSR_2NEIGH_TUPLE *data, *param;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  param = (OLSR_2NEIGH_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_local_iface_addr,
                   &param->N2_local_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_neighbor_iface_addr,
                   &param->N2_neighbor_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_2hop_iface_addr,
                   &param->N2_2hop_iface_addr));
}



void delete_2neigh_set_for_neighbor(struct olsrv2 *olsr,
                    const union olsr_ip_addr *local_iface_addr,
                    const union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_2NEIGH_TUPLE todelete;
  olsr_bool deleted_flag = OLSR_FALSE;
  int hash_index;


  olsr_ip_copy(olsr, &todelete.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &todelete.N2_neighbor_iface_addr, neighbor_iface_addr);

  for(hash_index = 0 ; hash_index < HASHSIZE; hash_index++)
    {
      if(OLSR_DeleteListHandler((void*)olsr,&olsr->two_neigh_set[hash_index].list, (void* )&todelete,
                &delete_2neigh_set_for_neighbor_handler) == OLSR_TRUE)
    deleted_flag = OLSR_TRUE;
    }

  if(deleted_flag){
    olsr->change_two_neigh_set = OLSR_TRUE;
  }
}

olsr_bool delete_2neigh_set_for_neighbor_handler(void *olsr,
                         void *arg_a, void *arg_b)
{
  const OLSR_2NEIGH_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  param = (OLSR_2NEIGH_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   (union olsr_ip_addr*)&data->N2_local_iface_addr,
                   (union olsr_ip_addr*)&param->N2_local_iface_addr)
             && equal_ip_addr((struct olsrv2 *)olsr,
                      (union olsr_ip_addr*)&data->N2_neighbor_iface_addr,
                      (union olsr_ip_addr*)&param->N2_neighbor_iface_addr));
}

OLSR_LIST *
search_2neigh_set(struct olsrv2 *olsr,
          const union olsr_ip_addr *local_iface_addr,
          union olsr_ip_addr *source_addr,
          const union olsr_ip_addr *two_nei_addr)
{
  OLSR_LIST *result;
  OLSR_2NEIGH_TUPLE search;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_neighbor_iface_addr, source_addr);
  olsr_ip_copy(olsr, &search.N2_2hop_iface_addr, two_nei_addr);

  result =
    OLSR_SearchList((void*)olsr,&olsr->two_neigh_set[olsr_hashing(olsr,source_addr)].list,
            (void* )&search, &search_2neigh_set_handler);

  return result;
}


olsr_bool
search_2neigh_set_for_exist(struct olsrv2 *olsr,
                const union olsr_ip_addr *local_iface_addr,
                union olsr_ip_addr *source_addr,
                const union olsr_ip_addr *two_nei_addr)
{
  OLSR_2NEIGH_TUPLE search;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_neighbor_iface_addr, source_addr);
  olsr_ip_copy(olsr, &search.N2_2hop_iface_addr, two_nei_addr);

  return OLSR_CheckMatchExist((void*)olsr,&olsr->two_neigh_set[olsr_hashing(olsr,source_addr)].list,
            (void* )&search, &search_2neigh_set_handler);
}


olsr_bool search_2neigh_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_2NEIGH_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  param = (OLSR_2NEIGH_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_local_iface_addr,
                   &param->N2_local_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_neighbor_iface_addr,
                   &param->N2_neighbor_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_2hop_iface_addr,
                   &param->N2_2hop_iface_addr));
}

OLSR_LIST *
search_2neigh_set_for_mpr_n(struct olsrv2 *olsr,
                const union olsr_ip_addr *local_iface_addr,
                union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_LIST *result = NULL;
  OLSR_2NEIGH_TUPLE search;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_neighbor_iface_addr, neighbor_iface_addr);

  result =
    OLSR_SearchList((void*)olsr,&olsr->two_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
           (void* ) &search, &search_2neigh_set_for_mpr_n_handler);

  return result;
}

olsr_bool
search_2neigh_set_for_mpr_n_for_exist(struct olsrv2 *olsr,
                      const union olsr_ip_addr *local_iface_addr,
                      union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_2NEIGH_TUPLE search;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_CheckMatchExist((void*)olsr,&olsr->two_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
            (void* )&search, &search_2neigh_set_for_mpr_n_handler);
}
int
check_2neigh_set_for_mpr_n_exist_num_entry(struct olsrv2 *olsr,
                        const union olsr_ip_addr *local_iface_addr,
                        union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_2NEIGH_TUPLE search;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_CheckMatchEntryNum((void*)olsr,&olsr->two_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
                 (void* )&search, &search_2neigh_set_for_mpr_n_handler);
}

olsr_bool search_2neigh_set_for_mpr_n_handler(void *olsr,
                          void *arg_a, void *arg_b)
{
  OLSR_2NEIGH_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  param = (OLSR_2NEIGH_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_local_iface_addr,
                   &param->N2_local_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_neighbor_iface_addr,
                   &param->N2_neighbor_iface_addr));
}

OLSR_LIST *
search_2neigh_set_for_mpr_n2(struct olsrv2 *olsr,
                 const union olsr_ip_addr *local_iface_addr,
                 const union olsr_ip_addr *two_hop_iface_addr)
{
  OLSR_LIST *result = NULL, *retList = NULL;
  OLSR_2NEIGH_TUPLE search;
  retList = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  int hash_index;

  olsr_ip_copy(olsr, &search.N2_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N2_2hop_iface_addr, two_hop_iface_addr);

  OLSR_InitList(retList);
  for(hash_index = 0 ; hash_index < HASHSIZE; hash_index++)
    {
      result = OLSR_SearchList((void*)olsr,&olsr->two_neigh_set[hash_index].list,
                   (void* )&search, &search_2neigh_set_for_mpr_n2_handler);
      if(result){
    if(retList->numEntry == 0)
    {
      retList->numEntry = result->numEntry;
      retList->head = result->head;
      retList->tail = result->tail;
    }
      else
    {
      retList->numEntry += result->numEntry;
      retList->tail->next = result->head;
      result->head->prev = retList->tail;
      retList->tail = result->tail;
    }
    free(result);
    }
  }
    return retList;
}

olsr_bool search_2neigh_set_for_mpr_n2_handler(void *olsr,
                           void *arg_a, void *arg_b)
{
  OLSR_2NEIGH_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_2NEIGH_TUPLE *)arg_a;
  param = (OLSR_2NEIGH_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_local_iface_addr,
                   &param->N2_local_iface_addr) &&
             equal_ip_addr((struct olsrv2 *)olsr,
                   &data->N2_2hop_iface_addr,
                   &param->N2_2hop_iface_addr));
}

void print_2neigh_set(struct olsrv2 *olsr)
{
  int hash_index;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_2NEIGH_TUPLE *data = NULL;
  olsr_bool put_head = OLSR_FALSE;

  if(olsr->olsr_cnf->debug_level < 2)
    return;
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      entry = olsr->two_neigh_set[hash_index].list.head;
      while(entry){
    if(put_head == OLSR_FALSE){
      olsr_printf("--------------------------------------- 2-hop Neighbor Set -------------------------\n");
      if(olsr->olsr_cnf->ip_version == AF_INET)
        olsr_printf("%-25s %-25s %-25s %-20s\n",
           "N2_local_iface_addr", "N2_neighbor_iface_addr", "N2_2hop_iface_addr", "N2_time");
      else
        olsr_printf("%-46s %-46s %-46s %-20s\n",
           "N2_local_iface_addr", "N2_neighbor_iface_addr", "N2_2hop_iface_addr", "N2_time");
      put_head = OLSR_TRUE;
    }

    data = (OLSR_2NEIGH_TUPLE *)entry->data;
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN], str3[INET_ADDRSTRLEN];

      //inet_ntop(AF_INET, &data->N2_local_iface_addr.v4, str1, sizeof(str1));
      //inet_ntop(AF_INET, &data->N2_neighbor_iface_addr.v4, str2, sizeof(str2));
      //inet_ntop(AF_INET, &data->N2_2hop_iface_addr.v4, str3, sizeof(str3));
      //yowada
      ConvertIpv4AddressToString(data->N2_local_iface_addr.v4, str1);
      ConvertIpv4AddressToString(data->N2_neighbor_iface_addr.v4, str2);
      ConvertIpv4AddressToString(data->N2_2hop_iface_addr.v4, str3);
      char time[30];
      qualnet_print_clock_in_second(data->N2_time, time);
      olsr_printf("%-18s %-21s %-17s %s [sec]\n", str1, str2, str3, time);
    }else{
       char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN], str3[INET6_ADDRSTRLEN];

       //inet_ntop(AF_INET6, data->N2_local_iface_addr.v6.s6_addr, str1, sizeof(str1));
       //inet_ntop(AF_INET6, data->N2_neighbor_iface_addr.v6.s6_addr, str2, sizeof(str2));
       //inet_ntop(AF_INET6, data->N2_2hop_iface_addr.v6.s6_addr, str3, sizeof(str3));
       ConvertIpv6AddressToString(&data->N2_local_iface_addr.v6, str1, OLSR_FALSE);
       ConvertIpv6AddressToString(&data->N2_neighbor_iface_addr.v6, str2, OLSR_FALSE);
       ConvertIpv6AddressToString(&data->N2_2hop_iface_addr.v6, str3, OLSR_FALSE);
       char time[30];
       qualnet_print_clock_in_second(data->N2_time, time);
       olsr_printf("%-46s %-46s %-46s %s [sec]\n", str1, str2, str3, time);
    }//if
    entry = entry->next;
      }//while

    }//for

  if(put_head == OLSR_FALSE){
    olsr_printf("------------------------------ 2-hop Neighbor Set ----------------------------\n");
    olsr_printf("\t\tno entry.\n");
  }
  olsr_printf("\n");

}
}
