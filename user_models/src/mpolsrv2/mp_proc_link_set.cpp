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
#include "mp_olsr_list.h"
#include "mp_olsr_util.h"

#include "mp_proc_link_set.h"
#include "mp_proc_2neigh_set.h"
#include "mp_proc_symmetric_neighbor_set.h"

#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

/* static function prototypes */
static
void insert_link_set(struct olsrv2 *,
             union olsr_ip_addr*, union olsr_ip_addr*,
             double);
static
olsr_bool delete_link_set_for_timeout_handler(void*, void *, void *);

static
olsr_bool search_link_set_handler(void*, void *, void *);

static
olsr_bool search_link_set_local_handler(void*, void *, void *);
static
OLSR_LIST *search_link_set_for_timeout(struct olsrv2 *);
static
olsr_bool search_link_set_for_timeout_handler(void*, void *, void *);
static
olsr_bool search_link_set_for_symmetric_handler(void*, void *, void *);
static
void update_hysterisis(struct olsrv2*, OLSR_LINK_TUPLE*, olsr_bool);

static
olsr_bool link_set_sort(void* olsr,void* arg_a, void* arg_b);


// for search_link_set_for_symmetric
typedef struct
{
  olsr_time_t time;
  union olsr_ip_addr addr;
}SEARCH_LINK_SET_SYM_TUPLE;


/* function implimentations */
void init_link_set(struct olsrv2 *olsr)
{
  olsr->change_link_set = OLSR_FALSE;
  OLSR_InitList(&olsr->link_set);
}

void proc_link_set(struct olsrv2 *olsr,
           union olsr_ip_addr *local_iface_addr,
           union olsr_ip_addr *source_addr,
           olsr_u8_t link_status,
           olsr_u8_t willingness,
           double validity_time,
           double interval_time)
{
  OLSR_LINK_TUPLE *data = NULL;
  OLSR_LIST *retList = NULL;
  olsr_u8_t before, after;
  olsr_time_t time;
  get_current_time(olsr, &time);

  //8.1
  retList = search_link_set(olsr, source_addr);
  //retList = search_link_set_local(olsr, local_iface_addr, source_addr);

  //8.1.1
  if(retList == NULL){
    insert_link_set(olsr, local_iface_addr, source_addr, validity_time);
    data = (OLSR_LINK_TUPLE *)olsr->link_set.tail->data;
    olsr->change_link_set = OLSR_TRUE;
  }else{
    assert(retList->numEntry == 1);
    data = (OLSR_LINK_TUPLE *)retList->head->data;

    OLSR_DeleteList_Search(retList);
  }

  //8.1.2.1
  // if the node finds the address of the interface, which
  // received the HELLO message, in one of the address blocks
  // included in message, then the tuple is modified as follows:

  if(data != NULL){
    before = (olsr_u8_t) get_link_status(time,
                                         data->L_SYM_time,
                                         data->L_ASYM_time,
                                         data->L_LOST_LINK_time);


    //8.1.2.1.1
    if(link_status == LOST && before == SYMMETRIC){
      get_current_time(olsr, &data->L_SYM_time);
      update_time(&data->L_SYM_time, -1);
    }

    //8.1.2.1.2
    else if(link_status == SYMMETRIC || link_status == ASYMMETRIC){
      get_current_time(olsr, &data->L_SYM_time);
      update_time(&data->L_SYM_time, (olsr_32_t)validity_time);

      get_current_time(olsr, &data->L_time);
      update_time(&data->L_time,
                  (olsr_32_t)(validity_time + olsr->qual_cnf->neighbor_hold_time));
    }else{
    if(DEBUG_OLSRV2)
    {
        olsr_printf("%s: (%d) the tuple is not modified.\n",
           __FUNCTION__, __LINE__);
    }
    }
    //8.1.2.2
    get_current_time(olsr, &data->L_ASYM_time);
    update_time(&data->L_ASYM_time, (olsr_32_t)validity_time);

    //8.1.2.3
    data->L_time = olsr_max_time(data->L_time, data->L_ASYM_time);

    //8.1.3 (Additional)
    if(willingness == WILL_NEVER || willingness == WILL_LOW ||
       willingness == WILL_DEFAULT || willingness == WILL_HIGH ||
       willingness == WILL_ALWAYS){
      data->L_willingness = willingness;

    }else{
      data->L_willingness = WILL_DEFAULT;
    }

    after = (olsr_u8_t) get_link_status(time,
                                        data->L_SYM_time,
                                        data->L_ASYM_time,
                                        data->L_LOST_LINK_time);

    if(before != after)
      {
        olsr->change_link_set = OLSR_TRUE;
      }

  }else{
    olsr_error("...");
  }

  data->validity_time = validity_time;
  data->interval_time = interval_time;



  //metric hysteresis
  if(OLSR_LINK_METRIC == OLSR_TRUE)
    {
      update_hysterisis(olsr, data, OLSR_TRUE);
      OLSR_List_sort(olsr, &olsr->link_set, (OLSR_LIST_HANDLER)link_set_sort);
    }
}

olsr_bool link_set_sort(void* olsr, void* arg_a, void* arg_b)
{
  OLSR_LINK_TUPLE* data_A = NULL, *data_B = NULL;

  data_A = (OLSR_LINK_TUPLE* )arg_a;
  data_B = (OLSR_LINK_TUPLE* )arg_b;

  if(data_A->L_link_quality <= data_B->L_link_quality)
    {
      return OLSR_TRUE;
    }

  return OLSR_FALSE;
}


void
update_hysterisis(struct olsrv2* olsr,
          OLSR_LINK_TUPLE* data, olsr_bool received)
{
  olsr_time_t time;

  //link quality
  if(received)
    {
      data->h_count = 0;
      data->L_link_quality =
    (1 - HYST_SCALING) * data->L_link_quality + HYST_SCALING;
    }
  else
    {
      data->L_link_quality =
    (1 - HYST_SCALING) * data->L_link_quality;
    }

  //pending and LOST_LINK_time
  if(OLSR_HYSTERESIS == OLSR_TRUE)
    {
      if(data->L_link_pending == OLSR_TRUE &&
     data->L_link_quality > HYST_THRESHOLD_HIGH)
    {
      data->L_link_pending = OLSR_FALSE;
      get_current_time(olsr, &data->L_LOST_LINK_time);
      update_time(&data->L_LOST_LINK_time, -1);
    }
      else if(data->L_link_pending == OLSR_FALSE &&
          data->L_link_quality < HYST_THRESHOLD_LOW)
    {
      data->L_link_pending = OLSR_TRUE;
      get_current_time(olsr, &time);
      update_time(&time,(olsr_32_t)olsr->qual_cnf->neighbor_hold_time);
      data->L_LOST_LINK_time = olsr_min_time(data->L_time, time);
    }
      else
    {
      //unchanged
    }
    }
}




void proc_link_layer_notification(struct olsrv2 *olsr,
                  union olsr_ip_addr neigh_iface_addr
                  )
{
  OLSR_LIST *retList = NULL;
  OLSR_LINK_TUPLE *data = NULL;

  retList = search_link_set(olsr, &neigh_iface_addr);
  if(retList != NULL){
    assert(retList->numEntry == 1);
    //WIN FIX: explicit typecast required
    data = (OLSR_LINK_TUPLE *)retList->tail->data;
  /* Let's Start to process link layer notification! */
    get_current_time(olsr, &data->L_LOST_LINK_time);
    update_time(&data->L_LOST_LINK_time,(olsr_32_t)olsr->qual_cnf->neighbor_hold_time);

    if(DEBUG_OLSRV2)
    {
    olsr_printf("%s: Change Link Status!!\n", __FUNCTION__);
    }

    delete_2neigh_set_for_neighbor(olsr,
                   &data->L_local_iface_addr,
                   &data->L_neighbor_iface_addr);

    if(DEBUG_OLSRV2)
    {
    olsr_printf("%s: Delete 2hop neighbor set!!\n", __FUNCTION__);
    }

    OLSR_DeleteList_Search(retList);

    olsr->change_link_set = OLSR_TRUE;
  }else{

      if(DEBUG_OLSRV2)
      {
      olsr_printf("%s: No Such Link!!\n", __FUNCTION__);
      }
  }
  /* for debug
  print_link_set(olsr);
  print_2neigh_set(olsr);
  */
  olsr_process_changes(olsr);
}

void insert_link_set(struct olsrv2 *olsr,
             union olsr_ip_addr *local_iface_addr,
             union olsr_ip_addr *source_addr,
             double vtime)
{
  OLSR_LINK_TUPLE data;
//MEMSET & Initializing other variables For Linux mismatch
  memset(&data,0,sizeof(OLSR_LINK_TUPLE));

  data.L_link_pending = OLSR_TRUE;
  data.validity_time = 0;
  data.interval_time = 0;
  data.h_count = 0;
  data.L_willingness = WILL_NEVER;
//MEMSET & Initializing other variables For Linux mismatch END

  data.L_neighbor_iface_addr = *source_addr;
  data.L_local_iface_addr = *local_iface_addr;
  data.L_link_quality = HYST_SCALING;

  get_current_time(olsr, &data.L_SYM_time);
  update_time(&data.L_SYM_time, (olsr_32_t)-1);

//Added for Solaris Crash
  get_current_time(olsr, &data.L_ASYM_time);
  update_time(&data.L_ASYM_time, (olsr_32_t)-1);

  get_current_time(olsr, &data.L_time);
  update_time(&data.L_time, (olsr_32_t)(vtime + olsr->qual_cnf->neighbor_hold_time));

  get_current_time(olsr, &data.L_LOST_LINK_time);
  update_time(&data.L_LOST_LINK_time, (olsr_32_t)-1);

  OLSR_InsertList(&olsr->link_set, &data, sizeof(OLSR_LINK_TUPLE));
}


void check_link_hysteresis(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_LINK_TUPLE* data = NULL;
  olsr_time_t time;

  tmp = olsr->link_set.head;

  while(tmp)
    {
      data = (OLSR_LINK_TUPLE* )tmp->data;

      get_current_time(olsr, &time);
      update_time(&time, (olsr_32_t)(data->validity_time - (data->interval_time*(data->h_count+1) + MAXJITTER)));

      if(olsr_cmp_time(time, data->L_ASYM_time) > 0)
    {
      data->h_count++;
      update_hysterisis(olsr, data, OLSR_FALSE);
    }
      tmp = tmp->next;
    }

  if(olsr->link_set.head)
    {
      OLSR_List_sort(olsr, &olsr->link_set, link_set_sort);
    }
}

void delete_link_set_for_timeout(struct olsrv2 *olsr)
{
  OLSR_LIST *retList = NULL;
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_LINK_TUPLE *data = NULL;
  olsr_bool deleted_flag;

//WIN FIX: Changed the variable name start
  void *todelete = (void *)olsr_malloc(sizeof(olsr_time_t), __FUNCTION__);

  olsr_time_t time;
  get_current_time(olsr, &time);

  memset(todelete, 0, sizeof(olsr_time_t));
  memcpy(todelete, &time, sizeof(olsr_time_t));

  if((retList = search_link_set_for_timeout(olsr)) != NULL){
    tmp = retList->head;
     while(tmp){
       data = (OLSR_LINK_TUPLE *)tmp->data;
       delete_2neigh_set_for_neighbor(olsr,
                      &data->L_local_iface_addr,
                      &data->L_neighbor_iface_addr);
       tmp = tmp->next;
     }

     OLSR_DeleteList_Search(retList);
  }

  deleted_flag =
           OLSR_DeleteListHandler((void*)olsr,&olsr->link_set, (void* )todelete,
           &delete_link_set_for_timeout_handler);
  if(deleted_flag){
    olsr->change_link_set = OLSR_TRUE;
  }
  free(todelete);
  //WIN FIX: Changed the variable name end
}

olsr_bool delete_link_set_for_timeout_handler(void* olsr,
                          void *arg_a, void *arg_b)
{
  OLSR_LINK_TUPLE *data = NULL;
//WIN FIX: Changed the variable name start
  olsr_time_t *todelete = NULL;

  data = (OLSR_LINK_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  //WIN FIX: explicit typecast required
  return (olsr_bool)(olsr_cmp_time(data->L_time, *todelete) < 0);
//WIN FIX: Changed the variable name end
}


OLSR_LIST *
search_link_set(struct olsrv2 *olsr,
        union olsr_ip_addr *neighbor_addr)
{

  return OLSR_SearchList((void*)olsr,&olsr->link_set,
             (void* )neighbor_addr,
             &search_link_set_handler);
 }


olsr_bool search_link_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_LINK_TUPLE *data = NULL;
  union olsr_ip_addr *neighbor_addr = NULL;

  data = (OLSR_LINK_TUPLE *)arg_a;
  neighbor_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
               &data->L_neighbor_iface_addr, neighbor_addr));
}

OLSR_LIST *
search_link_set_local(struct olsrv2 *olsr,
              union olsr_ip_addr *local_addr,
               union olsr_ip_addr *neighbor_addr)
{
  OLSR_LIST *result = NULL;
  //WIN FIX: explicit typecast required
  char *search = (char *)olsr_malloc(sizeof(union olsr_ip_addr)*2, __FUNCTION__);
  memcpy(search, local_addr, sizeof(union olsr_ip_addr));
  search += sizeof(union olsr_ip_addr);
  memcpy(search, neighbor_addr, sizeof(union olsr_ip_addr));
  search -= sizeof(union olsr_ip_addr);

  //olsr_ip_copy(search->L_local_iface_addr, local_addr);
  //olsr_ip_copy(search->L_neighbor_iface_addr, neighbor_addr);


  result = OLSR_SearchList((void*)olsr,&olsr->link_set,
             (void* )search, &search_link_set_local_handler);
  free(search);
  return result;
}

olsr_bool search_link_set_local_for_exist(struct olsrv2 *olsr,
                       union olsr_ip_addr *local_addr,
                       union olsr_ip_addr *neighbor_addr)
{
  OLSR_LINK_TUPLE search;
  olsr_ip_copy(olsr, &search.L_local_iface_addr, local_addr);
  olsr_ip_copy(olsr, &search.L_neighbor_iface_addr, neighbor_addr);

  return OLSR_CheckMatchExist((void*)olsr,&olsr->link_set,
                  (void* )&search, &search_link_set_local_handler);
}

olsr_bool search_link_set_local_handler(void* olsr,
                    void *arg_a, void *arg_b)
{
  OLSR_LINK_TUPLE *data = (OLSR_LINK_TUPLE *)arg_a;
  OLSR_LINK_TUPLE *param = (OLSR_LINK_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->L_local_iface_addr,
                   &param->L_local_iface_addr) &&
             equal_ip_addr((struct olsrv2* )olsr,
                   &data->L_neighbor_iface_addr,
                   &param->L_neighbor_iface_addr));

}

OLSR_LIST *
search_link_set_for_timeout(struct olsrv2 *olsr)
{
  olsr_time_t time;
  OLSR_LIST *result = NULL;

  get_current_time(olsr, &time);

  result = OLSR_SearchList((void*)olsr,&olsr->link_set,
               (void* )&time, &search_link_set_for_timeout_handler);

  return result;
}

olsr_bool search_link_set_for_timeout_handler(void* olsr,
                          void *arg_a, void *arg_b)
{
  OLSR_LINK_TUPLE *data = NULL;
  olsr_time_t *todelete = NULL;

  data = (OLSR_LINK_TUPLE *)arg_a;
  todelete = (olsr_time_t *)arg_b;

  return (olsr_bool)(olsr_cmp_time(data->L_time, *todelete) < 0);
}



OLSR_LIST *search_link_set_for_symmetric(struct olsrv2 *olsr,
                     union olsr_ip_addr *neighbor_addr)
{
  SEARCH_LINK_SET_SYM_TUPLE search;
  OLSR_LIST *result = NULL;

  get_current_time(olsr, &search.time);
  olsr_ip_copy(olsr, &search.addr, neighbor_addr);
  result = OLSR_SearchList((void*)olsr,&olsr->link_set,
               (void*) &search,
               &search_link_set_for_symmetric_handler);

  return result;
}

olsr_bool search_link_set_for_symmetric_exist(struct olsrv2 *olsr,
                           union olsr_ip_addr *neighbor_addr)
{
  SEARCH_LINK_SET_SYM_TUPLE search;
  olsr_bool exist;

  get_current_time(olsr, &search.time);

  olsr_ip_copy(olsr, &search.addr, neighbor_addr);
  exist  = OLSR_CheckMatchExist((void*)olsr,&olsr->link_set,
                (void* )&search,
                &search_link_set_for_symmetric_handler);

  return exist;
}

olsr_bool search_link_set_for_symmetric_handler(void* olsr,
                        void *arg_a, void *arg_b)
{
  OLSR_LINK_TUPLE *data = NULL;
  SEARCH_LINK_SET_SYM_TUPLE *param = NULL;
  data = (OLSR_LINK_TUPLE *)arg_a;
  param = (SEARCH_LINK_SET_SYM_TUPLE *) arg_b;

  return (olsr_bool) (equal_ip_addr((struct olsrv2* )olsr,
                    &data->L_neighbor_iface_addr,
                    &param->addr) &&
              get_link_status(param->time,
                      data->L_SYM_time,
                      data->L_ASYM_time,
                      data->L_LOST_LINK_time) == SYMMETRIC);
}

void print_link_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_LINK_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;
  tmp = olsr->link_set.head;

  if(tmp == NULL){
    olsr_printf("--- Link Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("----------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];

      olsr_printf("------------------------------------------------------ Link Set ------------------------------------------------------\n");
      olsr_printf("%-18s %-21s %-20s %-20s %-13s %-20s %-16s\n",
         "L_local_iface_addr", "L_neighbor_iface_addr", "L_SYM_time",
         "L_ASYM_time", "L_willingness", "L_time", "hysteresis");
      olsr_printf("----------------------------------------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_LINK_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->L_local_iface_addr.v4, str1, sizeof(str1));
    //inet_ntop(AF_INET, &data->L_neighbor_iface_addr.v4, str2, sizeof(str2));
    //yowada
    ConvertIpv4AddressToString(data->L_local_iface_addr.v4, str1);
    ConvertIpv4AddressToString(data->L_neighbor_iface_addr.v4, str2);

    char time1[30], time2[30], time3[30], time4[30];
    qualnet_print_clock_in_second(data->L_SYM_time, time1);
    qualnet_print_clock_in_second(data->L_ASYM_time, time2);
    qualnet_print_clock_in_second(data->L_time, time3);
    qualnet_print_clock_in_second(data->L_LOST_LINK_time, time4);

    olsr_printf("%-18s %-21s %s [sec] %s [sec] %-13d %s [sec] %lf\n",
           str1, str2, time1, time2, data->L_willingness, time3, data->L_link_quality);
    tmp = tmp->next;
      }

      olsr_printf("----------------------------------------------------------------------------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      olsr_printf("-------------------------------------------------------------------------------- Link Set --------------------------------------------------------------------------------\n");
      olsr_printf("%-46s %-46s %-20s %-20s %-13s %-20s %-16s\n",
         "L_local_iface_addr", "L_neighbor_iface_addr", "L_SYM_time",
         "L_ASYM_time", "L_willingness", "L_time", "hysteresis");
      olsr_printf("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_LINK_TUPLE *)tmp->data;

    char time1[30], time2[30], time3[30], time4[30];

    qualnet_print_clock_in_second(data->L_SYM_time, time1);
    qualnet_print_clock_in_second(data->L_ASYM_time, time2);
    qualnet_print_clock_in_second(data->L_time, time3);
    qualnet_print_clock_in_second(data->L_LOST_LINK_time, time4);

    char* paddr = olsr_niigata_ip_to_string(olsr, &data->L_local_iface_addr);
    olsr_printf("%-46s ", paddr);
    free(paddr);
    paddr = olsr_niigata_ip_to_string(olsr, &data->L_neighbor_iface_addr);
    olsr_printf("%-46s ", paddr);
    free(paddr);
    olsr_printf("%s [sec] %s [sec] %-13d %s [sec] %s [sec]\n",
           time1, time2, data->L_willingness, time3, time4);

    tmp = tmp->next;
      }

      olsr_printf("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}


int lookup_link_status(struct olsrv2 *olsr, union olsr_ip_addr *addr)
{
  OLSR_LIST *ret = NULL;
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *data = NULL;

  olsr_time_t time;

  get_current_time(olsr, &time);

  if((ret = search_symmetric_neighbor_set_for_neighbor(olsr, addr)) == NULL)
  {
      //olsr_printf("unspec\n");
    return UNSPEC;
  }
  data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)ret->head->data;
  OLSR_DeleteList_Search(ret);
  //check lost link
  /* Link Layer notification  */
  if(olsr_cmp_time(data->N_SYM_time, time) >= 0)
    return SYMMETRIC;
  else{
    return LOST;
  }
}


OLSR_LINK_TUPLE *lookup_link_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *addr)
{
  OLSR_LIST *retList = NULL;
  OLSR_LINK_TUPLE *data = NULL;

  retList = search_link_set(olsr,addr);
  if(retList == NULL)
    return NULL;
  else
    data = (OLSR_LINK_TUPLE *)retList->head->data;
  OLSR_DeleteList_Search(retList);

  return data;
}
}
