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
#include "mp_proc_mpr_selector_set.h"
#include "mp_proc_link_set.h"
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"
#include "mp_proc_symmetric_neighbor_set.h"

#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

/* static function prototypes */
static
void insert_mpr_selector_set(struct olsrv2 *,
                 union olsr_ip_addr *);
static
OLSR_LIST *search_mpr_selector_set(struct olsrv2 *,
                   union olsr_ip_addr *);
static
olsr_bool delete_mpr_selector_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool delete_mpr_selector_set_for_MS_addr(void *, void *, void *);
static
olsr_bool search_mpr_selector_set_handler(void *, void *, void *);


/* function implimentations */
void init_mpr_selector_set(struct olsrv2 *olsr)
{

  olsr->change_mpr_selector_set = OLSR_FALSE;
  OLSR_InitList(&olsr->mpr_selector_set);
}

void proc_mpr_selector_set(struct olsrv2 *olsr,
               union olsr_ip_addr *adv_neighbor_addr)
{
  OLSR_MPR_SELECTOR_TUPLE *data = NULL;

  OLSR_LIST *retList = NULL;

  retList = search_mpr_selector_set(olsr,
                    adv_neighbor_addr);


  if(retList != NULL){
    data = (OLSR_MPR_SELECTOR_TUPLE *)retList->head->data;

    get_current_time(olsr, &data->MS_time);
    update_time(&data->MS_time,(olsr_32_t)olsr->qual_cnf->neighbor_hold_time);

    OLSR_DeleteList_Search(retList);
  }

  else{
    insert_mpr_selector_set(olsr,
                adv_neighbor_addr);

  }
}

void insert_mpr_selector_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *adv_neighbor_addr)
{
  OLSR_MPR_SELECTOR_TUPLE data;

  data.MS_neighbor_if_addr = *adv_neighbor_addr;

  get_current_time(olsr, &data.MS_time);
  update_time(&data.MS_time,(olsr_32_t)olsr->qual_cnf->neighbor_hold_time);


  olsr->change_mpr_selector_set = OLSR_TRUE;

  OLSR_InsertList(&olsr->mpr_selector_set, &data, sizeof(OLSR_MPR_SELECTOR_TUPLE));
}



OLSR_LIST* delete_mpr_selector_set_for_linkbreakage(struct olsrv2 *olsr)
{
  OLSR_LIST *newList = (OLSR_LIST*)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  memset(newList, 0, sizeof(OLSR_LIST));

  OLSR_LIST_ENTRY* prev = NULL, *current = NULL, *tmp = NULL;
  OLSR_MPR_SELECTOR_TUPLE* data = NULL;

  if(newList->head){
    OLSR_DeleteList_Static(newList);
    OLSR_InitList(newList);
  }

  prev = NULL;
  current = olsr->mpr_selector_set.head;
  while(current != NULL)
  {
      data = (OLSR_MPR_SELECTOR_TUPLE* )current->data;
      if(search_symmetric_neighbor_set_for_symmetric_exist(olsr,
                               &data->MS_neighbor_if_addr) == OLSR_FALSE)
    {
      tmp = current->next;;
      olsr->mpr_selector_set.numEntry--;
      if(prev == NULL)
      {
        olsr->mpr_selector_set.head = current->next;
      }
      else
      {
          prev->next = current->next;
      }
      if(current->next)
      {
          current->next->prev = prev;
      }
      if(current == olsr->mpr_selector_set.tail)
      {
          olsr->mpr_selector_set.tail = prev;
      }


      if(newList->tail == NULL)
      {
          newList->tail = current;
      }
      current->prev = NULL;
      current->next = newList->head;
      if(newList->head)
      {
          newList->head->prev = current;
      }
      newList->head = current;
      newList->numEntry++;
      olsr->change_mpr_selector_set = OLSR_TRUE;

      current = tmp;
      }
      else
      {
    prev = current;
    current = current->next;
      }
  }

  return (newList);
}


OLSR_LIST* delete_mpr_selector_set_for_timeout(struct olsrv2 *olsr)
{
  //WIN FIX: Changed the variable name start
  void *todelete = (void *)malloc(sizeof(olsr_time_t));
  OLSR_LIST *result = NULL;
  //static OLSR_LIST newList;
  OLSR_LIST *newList = (OLSR_LIST*)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  memset(newList, 0, sizeof(OLSR_LIST));

  olsr_time_t time;
  get_current_time(olsr, &time);

  memset(todelete, 0, sizeof(olsr_time_t));
  memcpy(todelete, &time, sizeof(olsr_time_t));

  if(newList->head){
    OLSR_DeleteList_Static(newList);
    OLSR_InitList(newList);
  }

  result = OLSR_SearchList(olsr, &olsr->mpr_selector_set,
               todelete,
               &delete_mpr_selector_set_for_timeout_handler);
  if(result){
    assert(!newList->head);
    OLSR_CopyList(newList, result);

    OLSR_DeleteListHandler(olsr, &olsr->mpr_selector_set, todelete,
               &delete_mpr_selector_set_for_timeout_handler);
    olsr->change_mpr_selector_set = OLSR_TRUE;
    OLSR_DeleteList_Search(result);
  }

  free(todelete);
  //WIN FIX: Changed the variable name end
  return (newList);



/* //OLD CODE
  if(newList.head){
    OLSR_DeleteList_Static(&newList);
    OLSR_InitList(&newList);
  }

  result = OLSR_SearchList(olsr, &olsr->mpr_selector_set,
               todelete,
               &delete_mpr_selector_set_for_timeout_handler);
  if(result){
    assert(!newList.head);
    OLSR_CopyList(olsr, &newList, result);

    OLSR_DeleteListHandler(olsr, &olsr->mpr_selector_set, todelete,
               &delete_mpr_selector_set_for_timeout_handler);
    olsr->change_mpr_selector_set = OLSR_TRUE;
    OLSR_DeleteList_Search(result);
  }

  free(todelete);
  //WIN FIX: Changed the variable name end
  return (&newList);*/
}

olsr_bool delete_mpr_selector_set_for_timeout_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_SELECTOR_TUPLE *data = NULL;
  olsr_time_t *todelete = NULL;

  data = (OLSR_MPR_SELECTOR_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->MS_time, *todelete) < 0);
}

void delete_mpr_selector_set(struct olsrv2 *olsr,
                   union olsr_ip_addr* addr)
{
    if(OLSR_DeleteListHandler((void*)olsr,&olsr->mpr_selector_set, (void* )addr,
                  &delete_mpr_selector_set_for_MS_addr))
    {
        olsr->change_mpr_selector_set = OLSR_TRUE;
    }
}

static
olsr_bool delete_mpr_selector_set_for_MS_addr(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_SELECTOR_TUPLE *data = NULL;
  union olsr_ip_addr* todelete = NULL;

  data = (OLSR_MPR_SELECTOR_TUPLE *)arg_a;
  todelete = (union olsr_ip_addr* )arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,&data->MS_neighbor_if_addr, todelete));
}


OLSR_LIST *
search_mpr_selector_set(struct olsrv2 *olsr,
            union olsr_ip_addr *adv_neighbor_addr)
{
  OLSR_LIST *result;
  result = OLSR_SearchList((void*)olsr,&olsr->mpr_selector_set,
               (void* )adv_neighbor_addr,
               &search_mpr_selector_set_handler);

  return result;
}

olsr_bool search_mpr_selector_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_SELECTOR_TUPLE *data = NULL;
  union olsr_ip_addr *adv_neighbor_addr = NULL;

  data = (OLSR_MPR_SELECTOR_TUPLE *)arg_a;
  adv_neighbor_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->MS_neighbor_if_addr,
                   adv_neighbor_addr));
}

void print_mpr_selector_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_MPR_SELECTOR_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp = olsr->mpr_selector_set.head;

  if(tmp == NULL){
    olsr_printf("--- Mpr_Selector Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("--------------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN];

      olsr_printf("--------------------------- MPR_Selector Set ----------------------------\n");
      olsr_printf("%-17s %-12s %-20s\n",
         "MS_iface_addr", "T_seq", "T_time");
      olsr_printf("---------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_SELECTOR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->MS_neighbor_if_addr.v4, str1, sizeof(str1));
    ConvertIpv4AddressToString(data->MS_neighbor_if_addr.v4, str1);
    char time[30];
    qualnet_print_clock_in_second(data->MS_time, time);
    olsr_printf("%-17s %s [sec]\n", str1, time);
    tmp = tmp->next;
      }

      olsr_printf("---------------------------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str1[INET6_ADDRSTRLEN];

      olsr_printf("-------------------------------------------------------- Mpr_Selector Set ---------------------------------------------------------\n");
      olsr_printf("%-46s %-12s %-20s\n",
         "MS_iface_addr", "T_seq", "T_time");
      olsr_printf("-------------------------------------------------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_SELECTOR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET6, data->MS_neighbor_if_addr.v6.s6_addr, str1, sizeof(str1));
    ConvertIpv6AddressToString(&data->MS_neighbor_if_addr.v6, str1, OLSR_FALSE);
    char time[30];
    qualnet_print_clock_in_second(data->MS_time, time);
    olsr_printf("%-46s %s [sec]\n", str1, time);
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
