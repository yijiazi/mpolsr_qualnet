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
#include "mp_proc_symmetric_neighbor_set.h"

#include <stdio.h>
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
#include "mp_parse_address.h"

#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

/* static function prototypes */
static void insert_symmetric_neighbor_set(struct olsrv2 *,
                      const union olsr_ip_addr *,
                      const union olsr_ip_addr *,
                      double);
static olsr_bool search_symmetric_neighbor_set_handler(void*, void *, void *);
static olsr_bool delete_symmetric_neighbor_set_for_timeout_handler(void*, void *, void *);

/* function definitions */
void init_symmetric_neighbor_set(struct olsrv2 *olsr)
{
  olsr->change_sym_neigh_set = OLSR_FALSE;
  OLSR_InitHashList(&olsr->sym_neigh_set[0]);
}

void insert_symmetric_neighbor_set(struct olsrv2 *olsr,
                   const union olsr_ip_addr *local_iface_addr,
                   const union olsr_ip_addr *neighbor_iface_addr,
                   double validity_time)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE data;

  data.N_local_iface_addr = *local_iface_addr;
  data.N_neighbor_iface_addr = *neighbor_iface_addr;

  get_current_time(olsr, &data.N_SYM_time);
  update_time(&data.N_SYM_time, (olsr_32_t)validity_time);
  //N_time = N_SYM_time + N_HOLD_TIME = current + validity + N_HOLD_TIME
  get_current_time(olsr, &data.N_time);
  update_time(&data.N_time,
            (olsr_32_t)(validity_time + olsr->qual_cnf->neighbor_hold_time));

  OLSR_InsertList(&olsr->sym_neigh_set[olsr_hashing(olsr,&data.N_neighbor_iface_addr)].list,
          &data,
          sizeof(OLSR_SYMMETRIC_NEIGHBOR_TUPLE));
}

OLSR_LIST *search_symmetric_neighbor_set(struct olsrv2 *olsr,
                     union olsr_ip_addr *local_iface_addr,
                     union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE search;

  olsr_ip_copy(olsr, &search.N_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_SearchList((void*)olsr,&olsr->sym_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
             (void* )&search,
             &search_symmetric_neighbor_set_handler);
}

olsr_bool search_symmetric_neighbor_set_for_neighbor_handler(void* olsr,
                        void *arg_a, void *arg_b)
{
    OLSR_SYMMETRIC_NEIGHBOR_TUPLE  *data = NULL;
    OLSR_SYMMETRIC_NEIGHBOR_TUPLE  *param = NULL;

    data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_a;
    param = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->N_neighbor_iface_addr,
                   &param->N_neighbor_iface_addr));
}

OLSR_LIST *search_symmetric_neighbor_set_for_neighbor(struct olsrv2 *olsr,
                     union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE  search;

  olsr_ip_copy(olsr, &search.N_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_SearchList((void*)olsr,&olsr->sym_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
             (void* )&search,
             &search_symmetric_neighbor_set_for_neighbor_handler);
}



olsr_bool search_symmetric_neighbor_set_for_exist(struct olsrv2 *olsr,
                          union olsr_ip_addr *local_iface_addr,
                          union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE search;

  olsr_ip_copy(olsr, &search.N_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_CheckMatchExist((void*)olsr,&olsr->sym_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
                  (void* )&search,
                  &search_symmetric_neighbor_set_handler);
}

int check_symmetric_neighbor_set_for_exist_num_entry(struct olsrv2 *olsr,
                              union olsr_ip_addr *local_iface_addr,
                              union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE search;

  olsr_ip_copy(olsr, &search.N_local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.N_neighbor_iface_addr, neighbor_iface_addr);

  return OLSR_CheckMatchEntryNum((void*)olsr,&olsr->sym_neigh_set[olsr_hashing(olsr,neighbor_iface_addr)].list,
                 (void* )&search,
                 &search_symmetric_neighbor_set_handler);
}

olsr_bool search_symmetric_neighbor_set_handler(void* olsr,
                        void *arg_a, void *arg_b)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_a;
  param = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr, &data->N_local_iface_addr,
                   &param->N_local_iface_addr) &&
             equal_ip_addr((struct olsrv2* )olsr, &data->N_neighbor_iface_addr,
                   &param->N_neighbor_iface_addr));
}

 /*
     this func assume that receiving address is in ans address block of the
     hello message, other than Local Interface Block
     Note : above check must be done after call this func.
  */
void proc_symmetric_neighbor_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *local_iface_addr,
                 olsr_u8_t link_status,
                 struct hello_message *hello)
{
  OLSR_LIST_ENTRY *local_iface_list = hello->local_iface_list.head;
  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *local_data = NULL;
  double validity_time = hello->vtime;
  //struct address_tuple *tmp_addr = olsr->local_interface_block_entry;
  OLSR_LIST *retList = NULL;
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL;
  olsr_time_t tmpTime;

  /*
    6.2.1
    receiving address have an TLV with TYPE == LINK_STATUS and
    VALUE == (HEARD or SYMMETRIC
  */
  if( link_status == SYMMETRIC ||
      link_status == ASYMMETRIC){
    //6.2.1.1
    while(local_iface_list){
      local_data = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)local_iface_list->data;
      retList = search_symmetric_neighbor_set(olsr, local_iface_addr,
                          &local_data->iface_addr);
      //6.2.1.1.1
      if(retList){
    if(retList->numEntry != 1)
      olsr_error("proc_symmetric_neighbor_set");
    data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)retList->head->data;
    OLSR_DeleteList_Search(retList);

    //update N_SYM_time & N_time
    get_current_time(olsr, &data->N_SYM_time);
    update_time(&data->N_SYM_time, (olsr_32_t)validity_time);

    get_current_time(olsr, &data->N_time);
    update_time(&data->N_time,
            (olsr_32_t)(validity_time + olsr->qual_cnf->neighbor_hold_time));
      }else{ //6.2.1.1.2
    insert_symmetric_neighbor_set(olsr, local_iface_addr,
                      &local_data->iface_addr,
                      validity_time);
    olsr->change_sym_neigh_set = OLSR_TRUE;
      }

      local_iface_list = local_iface_list->next;
    }//while

  }else if(link_status == LOST){//6.2.2
    //6.2.2.1
    while(local_iface_list != NULL){
      local_data = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)local_iface_list->data;
      retList = search_symmetric_neighbor_set(olsr, local_iface_addr,
                          &local_data->iface_addr);
      if(retList){
    if(retList->numEntry != 1)
      olsr_error("proc_symmetric_neighbor_set");
    data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)retList->head->data;
    OLSR_DeleteList_Search(retList);

    //update N_SYM_time & N_time
    get_current_time(olsr, &data->N_SYM_time);
    update_time(&data->N_SYM_time, -1);

    get_current_time(olsr, &tmpTime);
    update_time(&tmpTime,(olsr_32_t)olsr->qual_cnf->neighbor_hold_time);
        data->N_time = olsr_min_time(data->N_time, tmpTime);
      }

      local_iface_list = local_iface_list->next;
    }//while

  }
}

void delete_symmetric_neighbor_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  int hash_index;
  olsr_bool deleted_flag = OLSR_FALSE;

  get_current_time(olsr, &time);

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++){
    if(OLSR_DeleteListHandler((void*)olsr,&olsr->sym_neigh_set[hash_index].list,
                  (void* )&time,
                  &delete_symmetric_neighbor_set_for_timeout_handler) == OLSR_TRUE)
      deleted_flag = OLSR_TRUE;
  }
  if(deleted_flag)
    olsr->change_sym_neigh_set = OLSR_TRUE;
}

olsr_bool delete_symmetric_neighbor_set_for_timeout_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL;
  olsr_time_t *param = NULL;

  data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_a;
  param = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->N_time, *param) < 0);
}

void print_symmetric_neighbor_set(struct olsrv2 *olsr)
{
  int hash_index;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL;
  olsr_bool put_head = OLSR_FALSE;

  if(olsr->olsr_cnf->debug_level < 2)
  return;

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      entry = olsr->sym_neigh_set[hash_index].list.head;
      while(entry){
    if(put_head == OLSR_FALSE){
      olsr_printf("------------------------------ == SYMMETRIC NEIGHBOR SET == ----------------\n");
      if(olsr->olsr_cnf->ip_version == AF_INET)
        olsr_printf("%-25s %-25s %-20s %-20s\n",
           "N_local_iface_addr", "N_neighbor_iface_addr", "N_SYM_time", "N_time");
      else
        olsr_printf("%-46s %-46s %-20s %-20s\n",
           "N_local_iface_addr", "N_neighbor_iface_addr", "N_SYM_time", "N_time");
      put_head = OLSR_TRUE;
    }

    data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)entry->data;
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];

      //WIN FIX: Need to resolve this
      ConvertIpv4AddressToString(data->N_local_iface_addr.v4, str1);
      ConvertIpv4AddressToString(data->N_neighbor_iface_addr.v4, str2);

      char time1[30], time2[30];
      qualnet_print_clock_in_second(data->N_SYM_time, time1);
      qualnet_print_clock_in_second(data->N_time, time2);
      olsr_printf("%-25s %-25s %s [sec]  %s [sec]\n", str1, str2, time1, time2);
    }else{
      char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];

      //WIN FIX: Need to resolve this
      //inet_ntop(AF_INET6, data->AN_net_addr.v6.s6_addr, str1, sizeof(str1));
      //inet_ntop(AF_INET6, data->AN_gw_addr.v6.s6_addr, str2, sizeof(str2));
      ConvertIpv6AddressToString(&data->N_local_iface_addr.v6, str1, OLSR_FALSE);
      ConvertIpv6AddressToString(&data->N_local_iface_addr.v6, str2, OLSR_FALSE);

      char time1[30], time2[30];
      qualnet_print_clock_in_second(data->N_SYM_time, time1);
      qualnet_print_clock_in_second(data->N_time, time2);
      olsr_printf("%-25s %-25s %s [sec]  %s [sec]\n", str1, str2, time1, time2);
    }//if

    entry = entry->next;

      }//while
    }//for

  if(put_head == OLSR_FALSE){
    olsr_printf("----------------------------- == SYMMETRIC NEIGHBOR SET == ------\n");
    olsr_printf("\t\t no entry.\n");
  }

  olsr_printf("\n");

}

//リンクセットで削除していたものをシンメトリックネイバーセットから見るように拡張する

olsr_bool search_symmetric_neighbor_set_for_symmetric_exist(struct olsrv2 *olsr,
                                union olsr_ip_addr *neighbor_addr)
{
  SEARCH_SYMMETRIC_NEIGHBOR_SET_SYM_TUPLE search;
  olsr_bool exist;

  get_current_time(olsr, &search.time);

  olsr_ip_copy(olsr, &search.addr, neighbor_addr);
  exist  = OLSR_CheckMatchExist((void*)olsr,&olsr->sym_neigh_set[olsr_hashing(olsr, neighbor_addr)].list,
                (void* )&search,
                &search_symmetric_neighbor_set_for_symmetric_handler);

  return exist;
}

olsr_bool search_symmetric_neighbor_set_for_symmetric_handler(void* olsr,
                        void *arg_a, void *arg_b)
{
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL;
  SEARCH_SYMMETRIC_NEIGHBOR_SET_SYM_TUPLE *param = NULL;
  data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)arg_a;
  param = (SEARCH_SYMMETRIC_NEIGHBOR_SET_SYM_TUPLE *) arg_b;

  return (olsr_bool) (equal_ip_addr((struct olsrv2* )olsr,
                    &data->N_neighbor_iface_addr,
                    &param->addr) &&
              get_neighbor_status(&param->time,
                      &data->N_SYM_time) == SYMMETRIC);
}
}
