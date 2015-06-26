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
#include "mp_proc_mpr_set.h"

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

#include "mp_proc_link_set.h"
#include "mp_proc_2neigh_set.h"

#include "mp_olsr_util.h"
#include "mp_olsr_protocol.h"

#include "mp_olsr_util_inline.h"
#include "mp_proc_neighbor_address_association_set.h"
#include "random.h"

//#include "routing_olsrv2_niigata.h"

namespace MPOLSRv2{


extern int random(olsrv2 *olsr);
/*int random(struct olsrv2 *olsr)
{ 

    return (RANDOM_nrand(olsr->seed) % 32767);
}*/


/* static function prototypes */
static
OLSR_LIST *proc_mpr_set_per_interface(struct olsrv2 *,
                      union olsr_ip_addr *);

static
void insert_mpr_set(struct olsrv2 *,
            union olsr_ip_addr *, union olsr_ip_addr *);
static
void insert_mpr_set_per_interface(OLSR_LIST *,
                  union olsr_ip_addr *, union olsr_ip_addr *);

static
void insert_mprN(OLSR_LIST *,
         union olsr_ip_addr *,
         olsr_u32_t,
         olsr_u32_t,
         olsr_u8_t);
static
void insert_mprN2(OLSR_LIST *, union olsr_ip_addr *);


static
void update_mprN2_locally(struct olsrv2 *,
              OLSR_LIST *,
              union olsr_ip_addr *,
              union olsr_ip_addr *);

static
void update_mprN2(struct olsrv2 *,
          OLSR_LIST *, OLSR_LIST *, union olsr_ip_addr *);
/*
static
OLSR_LIST *search_mprN(OLSR_LIST *, union olsr_ip_addr *);
*/
static
olsr_bool search_mprN_for_exist(struct olsrv2* olsr, OLSR_LIST *, union olsr_ip_addr *);
/*
static
OLSR_LIST *search_mprN2(OLSR_LIST *, union olsr_ip_addr *);
*/
static
olsr_bool search_mprN2_for_exist(struct olsrv2*, OLSR_LIST *, union olsr_ip_addr *);

static
void delete_mpr_set_for_all_entry(struct olsrv2 *, union olsr_ip_addr*);
static
void delete_mprN2(struct olsrv2* olsr, OLSR_LIST *, union olsr_ip_addr *);

static
void print_mprN(struct olsrv2* olsr, OLSR_LIST *);
static
void print_mprN2(struct olsrv2* olsr, OLSR_LIST *);
static
void print_mpr_set_per_interface(struct olsrv2* olsr, OLSR_LIST *);

static
olsr_bool search_mpr_set_handler(void *, void *, void *);
static
olsr_bool search_mprN_handler(void *, void *, void *);
static
olsr_bool search_mprN2_handler(void *, void *, void *);

static
olsr_bool delete_mpr_set_for_all_entry_handler(void*, void *, void *);


static
olsr_bool delete_mprN2_handler(void *, void *, void *);
static
olsr_bool sort_mpr_set_handler(void* olsr, void* arg_a, void* arg_b);

/* function implimentations */
void init_mpr_set(struct olsrv2 *olsr)
{
  olsr->change_mpr_set = OLSR_FALSE;
  OLSR_InitList(&olsr->mpr_set);
}

olsr_bool check_recalculate_mpr_set(struct olsrv2 *olsr)
{
  //WIN FIX: explicit typecast required
  return (olsr_bool)(olsr->change_link_set || olsr->change_two_neigh_set);
}

void reset_recalculate_mpr_set(struct olsrv2 *olsr)
{
  olsr->change_link_set = olsr->change_two_neigh_set = OLSR_FALSE;
}

void proc_mpr_set(struct olsrv2 *olsr)
{
  OLSR_LIST *retMPR_set = NULL;
  OLSR_LIST_ENTRY *tmp = NULL;

  OLSR_MPR_TUPLE *mpr_data = NULL;

  union olsr_ip_addr* local_iface_addr = NULL;


  local_iface_addr = &olsr->iface_addr[olsr->parsingIfNum];
  //Appendix A
  delete_mpr_set_for_all_entry(olsr, local_iface_addr);
  //one interface of node
  //for local_iface_addr

  retMPR_set = proc_mpr_set_per_interface(olsr, local_iface_addr);
  tmp = retMPR_set->head;

  while(tmp != NULL){
      mpr_data = (OLSR_MPR_TUPLE *)tmp->data;
      insert_mpr_set(olsr,
             local_iface_addr, &mpr_data->MPR_if_addr);

      tmp = tmp->next;
  }
  OLSR_DeleteList(retMPR_set);

  if(DEBUG_OLSRV2)
  {
      print_mpr_set(olsr);
  }

  //print_mpr_set(olsr);
  olsr->change_mpr_set = OLSR_TRUE;
}

void insert_mpr_set(struct olsrv2 *olsr,
            union olsr_ip_addr *local_iface_addr,
            union olsr_ip_addr *MPR_if_addr)
{
  OLSR_MPR_TUPLE data;

  data.local_iface_addr = *local_iface_addr;
  data.MPR_if_addr = *MPR_if_addr;

  OLSR_InsertList_Sort(olsr,
               &olsr->mpr_set,
               &data,
               sizeof(OLSR_MPR_TUPLE),
               &sort_mpr_set_handler);
}

olsr_bool sort_mpr_set_handler(void* olsr, void* arg_a, void* arg_b)
{
  OLSR_MPR_TUPLE* data = NULL, *insert = NULL;

  data = (OLSR_MPR_TUPLE* )arg_a;
  insert = (OLSR_MPR_TUPLE* )arg_b;

  if(cmp_ip_addr((struct olsrv2* )olsr,
         &data->MPR_if_addr, &insert->MPR_if_addr) > 0)
    {
      return OLSR_TRUE;
    }

  return OLSR_FALSE;
}

OLSR_LIST *search_mpr_set(struct olsrv2 *olsr,
              union olsr_ip_addr *local_iface_addr,
              union olsr_ip_addr *MPR_if_addr)
{
  OLSR_MPR_TUPLE search;

  olsr_ip_copy(olsr, &search.local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.MPR_if_addr, MPR_if_addr);

  return OLSR_SearchList((void*)olsr,&olsr->mpr_set, (void* )&search, &search_mpr_set_handler);
}

olsr_bool search_mpr_set_for_exist(struct olsrv2 *olsr,
                   union olsr_ip_addr *local_iface_addr,
                   union olsr_ip_addr *MPR_if_addr)
{
  OLSR_MPR_TUPLE search;

  olsr_ip_copy(olsr, &search.local_iface_addr, local_iface_addr);
  olsr_ip_copy(olsr, &search.MPR_if_addr, MPR_if_addr);

  return OLSR_CheckMatchExist((void*)olsr,&olsr->mpr_set, (void* )&search, &search_mpr_set_handler);
}

olsr_bool search_mpr_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_TUPLE *data = NULL, *search = NULL;

  data = (OLSR_MPR_TUPLE *)arg_a;
  search = (OLSR_MPR_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->MPR_if_addr, &search->MPR_if_addr)
             && equal_ip_addr((struct olsrv2 *)olsr,
                      &data->local_iface_addr,
                      &search->local_iface_addr));
}

olsr_bool delete_mpr_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_TUPLE *data = NULL, *search = NULL;

  data = (OLSR_MPR_TUPLE *)arg_a;
  search = (OLSR_MPR_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr,
                   &data->local_iface_addr,
                   &search->local_iface_addr));
}

void delete_mpr_set_for_all_entry(struct olsrv2 *olsr,
                  union olsr_ip_addr* addr)
{
  OLSR_MPR_TUPLE todelete;

  todelete.local_iface_addr = *addr;

  OLSR_DeleteListHandler((void*)olsr,&olsr->mpr_set,
            &todelete, &delete_mpr_set_handler);
}


olsr_bool delete_mpr_set_for_all_entry_handler(void* olsr, void *arg_a, void *arg_b)
{
  return OLSR_TRUE;
}


OLSR_LIST *proc_mpr_set_per_interface(struct olsrv2 *olsr,
                      union olsr_ip_addr *local_iface_addr)
{
  OLSR_LIST *MPR_set = NULL, N, N2;

  OLSR_LIST *retList = NULL;
  OLSR_LIST_ENTRY *tmp = NULL, *retList_tmp = NULL;
  OLSR_LINK_TUPLE *link_data = NULL;
  OLSR_2NEIGH_TUPLE *two_neigh_data = NULL;
  OLSR_MPR_N_TUPLE *mpr_n_data = NULL;
  OLSR_MPR_N2_TUPLE *mpr_n2_data = NULL;

  int hash_index;
  olsr_time_t time;
  get_current_time(olsr, &time);

  if(DEBUG_OLSRV2)
  {
      olsr_printf("\n[Start MPR selection per interface]\n");
  }

  //Init MPR set
  MPR_set = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);
  OLSR_InitList(MPR_set);

  //Create MPR N
  // N - the set of such neighbor interfaces
  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Create N]\n");
      olsr_printf("[Appendix A.2]\n");
  }
  OLSR_InitList(&N);

  tmp = olsr->link_set.head;
  while(tmp != NULL){
    link_data = (OLSR_LINK_TUPLE *)tmp->data;
    if(link_data->L_willingness > WILL_NEVER &&
       get_link_status(time,
               link_data->L_SYM_time,
               link_data->L_ASYM_time,
               link_data->L_LOST_LINK_time) == SYMMETRIC){
      if(equal_ip_addr(olsr, &link_data->L_local_iface_addr,
               local_iface_addr)){


    if(search_mprN_for_exist(olsr, &N, &link_data->L_neighbor_iface_addr)
       == OLSR_FALSE){


      // Calculate D(y), where y is a member of N, for all interfaces in N.
      int retNum = check_2neigh_set_for_mpr_n_exist_num_entry(olsr, local_iface_addr,
                                &link_data->L_neighbor_iface_addr);
      if(retNum > 0){
        insert_mprN(&N, &link_data->L_neighbor_iface_addr,
            /*retList->numEntry*/retNum, 0,
            link_data->L_willingness);

      }
    }
      }
    }
    tmp = tmp->next;
  }

  //print_mprN(olsr, &N);

  //Create MPR N2
  // N2 - the set of such 2-hop neighbor interfaces
  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Create N2]\n");
  }

  OLSR_InitList(&N2);
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
    {
      tmp = olsr->two_neigh_set[hash_index].list.head;
      while(tmp != NULL){
    two_neigh_data = (OLSR_2NEIGH_TUPLE *)tmp->data;

    if(search_mprN_for_exist(olsr, &N, &two_neigh_data->N2_neighbor_iface_addr)
       == OLSR_TRUE &&
       search_association_set_for_addr_exist(olsr, &two_neigh_data->N2_2hop_iface_addr)
       == OLSR_FALSE){

      if(equal_ip_addr(olsr, &two_neigh_data->N2_local_iface_addr,
               local_iface_addr)){
        if(search_mprN_for_exist(olsr, &N, &two_neigh_data->N2_2hop_iface_addr)
           == OLSR_TRUE){
          tmp = tmp->next;
          continue;
        }


        if(search_mprN2_for_exist(olsr, &N2, &two_neigh_data->N2_2hop_iface_addr) == OLSR_FALSE)
        {
          insert_mprN2(&N2, &two_neigh_data->N2_2hop_iface_addr);
        }
      }

    }
    tmp = tmp->next;
      }
    }
  //print_mprN2(olsr, &N2);


  //Appendix A.1
  // Start with an MPR set made of all members of N with N_willingness
  // equal to WILL_ALWAYS
  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Appendix A.1]\n");
  }

  tmp = N.head;
  while(tmp != NULL){
    mpr_n_data = (OLSR_MPR_N_TUPLE *)tmp->data;
    if(mpr_n_data->willingness == WILL_ALWAYS)
      insert_mpr_set_per_interface(MPR_set, local_iface_addr, &mpr_n_data->addr);
    tmp = tmp->next;
  }

  update_mprN2(olsr,
           &N2, MPR_set, local_iface_addr);

  //print_mprN2(olsr, &N2);

  //Appendix A.3
  // Add to the MPR set those interfaces in N, which are the *only*
  // nodes to provide reachability to an interface in N2.  For
  // example, if interface B in N2 can be reached only through a
  // symmetric link to interface A in N, then add interface B to the
  // MPR set.  Remove the interfaces from N2 which are now covered by
  // a interface in the MPR set.
  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Appendix A.3]\n");
  }

  tmp = N2.head;
  while(tmp != NULL){
    mpr_n2_data = (OLSR_MPR_N2_TUPLE *)tmp->data;
    retList =
      search_2neigh_set_for_mpr_n2(olsr,
                   local_iface_addr,
                   &mpr_n2_data->addr);
    if(retList != NULL){
      if(retList->numEntry == 1){

    two_neigh_data = (OLSR_2NEIGH_TUPLE *)retList->head->data;
    insert_mpr_set_per_interface(MPR_set,
                     local_iface_addr,
                     &two_neigh_data->N2_neighbor_iface_addr);
    update_mprN2_locally(olsr,
                 &N2,
                 local_iface_addr,
                 &two_neigh_data->N2_neighbor_iface_addr);
    tmp = N2.head;
    OLSR_DeleteList_Search(retList);
    continue;
      }
      OLSR_DeleteList_Search(retList);
    }

    tmp = tmp->next;
  }

  //print_mprN2(olsr, &N2);

  //Appendix A.4
  // While there exist interfaces in N2 which are not covered by at
  // least one interface in the MPR set:
  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Appendix A.4]\n");
  }

  while(N2.head != NULL){
    //Appendix A.4.1
    // For each interface in N, calculate the reachability, i.e.,
    // the number of interfaces in N2 which are not yet covered by
    // at least one node in the MPR set, and which are reachable
    // through this neighbor interface;
    //OLSR_LIST *ret;

    olsr_u32_t max_willingness, max_reachability, max_D;
    olsr_u32_t i;
    union olsr_ip_addr mpr_addr;
    union olsr_ip_addr random_mpr[OLSR_MAX_DUPLICATE_MPR];

    memset(&mpr_addr, 0, sizeof(olsr_ip_addr));

    if(DEBUG_OLSRV2)
    {
    olsr_printf("[Appendix A.4.1]\n");
    }


    tmp = N.head;
    while(tmp != NULL){
      mpr_n_data = (OLSR_MPR_N_TUPLE *)tmp->data;
      mpr_n_data->reachability = 0;

      retList =
    search_2neigh_set_for_mpr_n(olsr,
                    local_iface_addr,
                    &mpr_n_data->addr);

      if(retList != NULL){
    retList_tmp = retList->head;
    while(retList_tmp != NULL){
      two_neigh_data = (OLSR_2NEIGH_TUPLE *)retList_tmp->data;

      if(search_mprN2_for_exist(olsr, &N2, &two_neigh_data->N2_2hop_iface_addr)
         == OLSR_TRUE){
        mpr_n_data->reachability++;
      }

      retList_tmp = retList_tmp->next;
    }
    OLSR_DeleteList_Search(retList);
      }

      tmp = tmp->next;
    }

    //print_mprN(olsr, &N);


    //Appendix A.4.2(XXX)
    // Select as a MPR the interface with highest N_willingness
    // among the interfaces in N with non-zero reachability.
    // In case of multiple choice select the interface which provides
    // reachability to the maximum number of interfaces in N2.
    // In case of multiple interfaces providing the same amount of
    // reachability, select the interface as MPR whose D(y) is
    // greater.
    // Remove the interfaces from N2 which are now covered by an interface in the MPR set.

    tmp = N.head;
    max_willingness = WILL_NEVER; //0
    max_reachability = 0;
    max_D = 0;
    i = 0;

    while(tmp != NULL){
      mpr_n_data = (OLSR_MPR_N_TUPLE *)tmp->data;

      if(mpr_n_data->reachability == 0){
    tmp = tmp->next;
    continue;
      }

      //check willingness
      if(mpr_n_data->willingness > max_willingness){
    max_willingness = mpr_n_data->willingness;
    max_reachability = mpr_n_data->reachability;
    max_D = mpr_n_data->D;
    i = 0;
    mpr_addr = mpr_n_data->addr;
      }
      else if(mpr_n_data->willingness == max_willingness){

    //check reachability
    if(mpr_n_data->reachability > max_reachability){
      max_reachability = mpr_n_data->reachability;
      max_D = mpr_n_data->D;
      i = 0;
      mpr_addr = mpr_n_data->addr;
    }
    else if(mpr_n_data->reachability == max_reachability){

      //check D(y)
      if(mpr_n_data->D > max_D){
        max_D = mpr_n_data->D;
        i = 0;
        mpr_addr = mpr_n_data->addr;
      }
      else if(mpr_n_data->D == max_D){

        if(i == 0){
          random_mpr[i++] = mpr_addr;
        }
        if(i < OLSR_MAX_DUPLICATE_MPR){
          random_mpr[i++] = mpr_n_data->addr;
        }

      }
    }
      }
      tmp = tmp->next;

    }// ....now checked duplication

    if(max_willingness == WILL_NEVER){
      olsr_error("MPR selection is wrong "
         "there is no MPR which have available willingness, "
         "or non-zero-reachability");
    }

    if(i != 0){
      i = (olsr_u32_t)(random(olsr)%i);
      mpr_addr = random_mpr[i];
    }

    insert_mpr_set_per_interface(MPR_set,
                 local_iface_addr,
                 &mpr_addr);

    update_mprN2_locally(olsr,
             &N2,
             local_iface_addr,
             &mpr_addr);

    //print_mpr_set_per_interface(olsr, MPR_set);
  }

  //print_mpr_set_per_interface(olsr, MPR_set);

  if(DEBUG_OLSRV2)
  {
      olsr_printf("[Complete MPR selection per interface]\n\n");
  }

  OLSR_DeleteList_Static(&N);
  OLSR_DeleteList_Static(&N2);

  return MPR_set;
}

void insert_mpr_set_per_interface(OLSR_LIST *list,
                  union olsr_ip_addr *local_iface_addr,
                  union olsr_ip_addr *MPR_if_addr)
{
  OLSR_MPR_TUPLE data;

  data.local_iface_addr = *local_iface_addr;
  data.MPR_if_addr = *MPR_if_addr;

  OLSR_InsertList(list, &data, sizeof(OLSR_MPR_TUPLE));

}

void insert_mprN(OLSR_LIST *list,
         union olsr_ip_addr *addr,
         olsr_u32_t D,
         olsr_u32_t reachability,
         olsr_u8_t willingness)
{
  OLSR_MPR_N_TUPLE data;

  data.addr = *addr;
  data.D = D;
  data.reachability = reachability;
  data.willingness = willingness;

  OLSR_InsertList(list, &data, sizeof(OLSR_MPR_N_TUPLE));
}

void insert_mprN2(OLSR_LIST *list, union olsr_ip_addr *addr)
{
  OLSR_MPR_N2_TUPLE data;

  data.addr = *addr;

  OLSR_InsertList(list, &data, sizeof(OLSR_MPR_N2_TUPLE));
}


void update_mprN2_locally(struct olsrv2 *olsr,
              OLSR_LIST *N2,
              union olsr_ip_addr *local_iface_addr,
              union olsr_ip_addr *MPR_if_addr)
{
  OLSR_LIST *retList = NULL;
  OLSR_LIST_ENTRY *retList_tmp = NULL;
  OLSR_2NEIGH_TUPLE *two_neigh_data = NULL;

  retList =
    search_2neigh_set_for_mpr_n(olsr,
                local_iface_addr,
                MPR_if_addr);
  if(retList != NULL){
    retList_tmp = retList->head;
    while(retList_tmp != NULL){
      two_neigh_data = (OLSR_2NEIGH_TUPLE *)retList_tmp->data;
      delete_mprN2(olsr, N2, &two_neigh_data->N2_2hop_iface_addr);
      retList_tmp = retList_tmp->next;
    }
    OLSR_DeleteList_Search(retList);
  }
}

void update_mprN2(struct olsrv2 *olsr,
          OLSR_LIST *N2,
          OLSR_LIST *MPR_set,
          union olsr_ip_addr *local_iface_addr)
{
  OLSR_LIST *retList = NULL;
  OLSR_LIST_ENTRY *tmp = NULL, *retList_tmp = NULL;

  OLSR_MPR_TUPLE *mpr_data = NULL;
  OLSR_2NEIGH_TUPLE *two_neigh_data = NULL;

  tmp = MPR_set->head;
    while(tmp != NULL){
      mpr_data = (OLSR_MPR_TUPLE *)tmp->data;
      retList =
    search_2neigh_set_for_mpr_n(olsr,
                    local_iface_addr,
                    &mpr_data->MPR_if_addr);
      if(retList != NULL){
    retList_tmp = retList->head;
    while(retList_tmp != NULL){
      two_neigh_data = (OLSR_2NEIGH_TUPLE *)retList_tmp->data;
      delete_mprN2(olsr, N2, &two_neigh_data->N2_2hop_iface_addr);
      retList_tmp = retList_tmp->next;
    }
    OLSR_DeleteList_Search(retList);
      }
      tmp = tmp->next;
    }
}


olsr_bool search_mprN_for_exist(struct olsrv2* olsr, OLSR_LIST *list, union olsr_ip_addr *addr)
{
  return OLSR_CheckMatchExist((void*)olsr,list, addr, &search_mprN_handler);
}

olsr_bool search_mprN_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_N_TUPLE *data = NULL;
  union olsr_ip_addr *search = NULL;

  data = (OLSR_MPR_N_TUPLE *)arg_a;
  search = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)equal_ip_addr((struct olsrv2 *)olsr, &data->addr, search);
}

olsr_bool search_mprN2_for_exist(struct olsrv2* olsr, OLSR_LIST *list, union olsr_ip_addr *addr)
{
  return OLSR_CheckMatchExist((void*)olsr,list, addr, &search_mprN2_handler);
}

olsr_bool search_mprN2_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_N2_TUPLE *data = NULL;
  union olsr_ip_addr *search = NULL;

  data = (OLSR_MPR_N2_TUPLE *)arg_a;
  search = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)equal_ip_addr((struct olsrv2 *)olsr, &data->addr, search);
}

void delete_mprN2(struct olsrv2* olsr, OLSR_LIST *list, union olsr_ip_addr *addr)
{
  OLSR_DeleteListHandler((void*)olsr,list, (void* )addr, &delete_mprN2_handler);
}

olsr_bool delete_mprN2_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_MPR_N2_TUPLE *data = NULL;
  union olsr_ip_addr *todelete = NULL;

  data = (OLSR_MPR_N2_TUPLE *)arg_a;
  todelete = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)equal_ip_addr((struct olsrv2 *)olsr, &data->addr, todelete);
}


void print_mprN(struct olsrv2* olsr, OLSR_LIST *N)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_MPR_N_TUPLE *data = NULL;

  tmp = N->head;
  if(tmp == NULL){
    olsr_printf("--- MPR N  ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("--------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str[INET_ADDRSTRLEN];

      olsr_printf("------------------------ MPR N -----------------------\n");
      olsr_printf("%-16s %-12s %-12s %-12s\n",
          "MPR_N_if_addr", "D", "reachability", "willingness");
      olsr_printf("------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_N_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->addr.v4, str, sizeof(str));
    //yowada
    ConvertIpv4AddressToString(data->addr.v4, str);
    olsr_printf("%-16s %-12u %-12u %-12u\n",
           str,
           data->D,
           data->reachability,
           data->willingness);
    tmp = tmp->next;
      }

      olsr_printf("------------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str[INET6_ADDRSTRLEN];

      olsr_printf("--------------------------------------- MPR N --------------------------------------\n");
      olsr_printf("%-46s %-12s %-12s %-12s\n",
          "MPR_N_if_addr", "D", "reachability", "willingness");
      olsr_printf("------------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_N_TUPLE *)tmp->data;
    //inet_ntop(AF_INET6, data->addr.v6.s6_addr, str, sizeof(str));
    ConvertIpv6AddressToString(&data->addr.v6, str, OLSR_FALSE);
    olsr_printf("%-46s %-12u %-12u %-12u\n",
            str,
            data->D,
            data->reachability,
            data->willingness);
    tmp = tmp->next;
      }

      olsr_printf("------------------------------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}


void print_mprN2(struct olsrv2* olsr, OLSR_LIST *N2)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_MPR_N_TUPLE *data = NULL;

  tmp = N2->head;
  if(tmp == NULL){
    olsr_printf( "--- MPR N2 ---\n");
    olsr_printf( "no entry.\n");
    olsr_printf( "--------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str[INET_ADDRSTRLEN];

      olsr_printf( "----- MPR N2 -----\n");
      olsr_printf( "%-16s\n", "MPR_N2_if_addr");
      olsr_printf( "------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_N_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->addr.v4, str, sizeof(str));
    ConvertIpv4AddressToString(data->addr.v4, str);
    olsr_printf( "%-16s\n", str);
    tmp = tmp->next;
      }

      olsr_printf( "------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str[INET6_ADDRSTRLEN];

      olsr_printf( "------------------- MPR N2 -------------------\n");
      olsr_printf( "%-46s\n", "MPR_N2_if_addr");
      olsr_printf( "----------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_N_TUPLE *)tmp->data;
    //inet_ntop(AF_INET6, data->addr.v6.s6_addr, str, sizeof(str));
    ConvertIpv6AddressToString(&data->addr.v6, str, (olsr_bool)false);
    olsr_printf( "%-46s\n", str);
    tmp = tmp->next;
      }

      olsr_printf( "----------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}

void print_mpr_set_per_interface(struct olsrv2* olsr, OLSR_LIST *MPR_set)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_MPR_TUPLE *data = NULL;

  tmp = MPR_set->head;
  if(tmp == NULL){
    olsr_printf( "--- MPR Set per Interface ---\n");
    olsr_printf( "no entry.\n");
    olsr_printf( "-----------------------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];

      olsr_printf( "------------ MPR Set per Interface ------------\n");
      olsr_printf( "%-20s %-16s\n", "local_iface_addr", "MPR_if_addr");
      olsr_printf( "-----------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->local_iface_addr.v4, str1, sizeof(str1));
    //inet_ntop(AF_INET, &data->MPR_if_addr.v4, str2, sizeof(str2));
    ConvertIpv4AddressToString(data->local_iface_addr.v4, str1);
    ConvertIpv4AddressToString(data->MPR_if_addr.v4, str2);
    olsr_printf( "%-20s %-16s\n", str1, str2);

    tmp = tmp->next;
      }

      olsr_printf( "----------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];

      olsr_printf( "--------------------------- MPR Set per Interface ---------------------------\n");
      olsr_printf( "%-46s %-46s\n", "local_iface_addr", "MPR_if_addr");
      olsr_printf( "-----------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET6,
    //    data->local_iface_addr.v6.s6_addr, str1, sizeof(str1));
    //inet_ntop(AF_INET6,
    //    data->MPR_if_addr.v6.s6_addr, str2, sizeof(str2));
    ConvertIpv6AddressToString(&data->local_iface_addr.v6, str1, (olsr_bool)false);
    ConvertIpv6AddressToString(&data->MPR_if_addr.v6, str2, (olsr_bool)false);
    olsr_printf( "%-46s %-46s\n", str1, str2);
    tmp = tmp->next;
      }

      olsr_printf( "-----------------------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}


void print_mpr_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_MPR_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp = olsr->mpr_set.head;
  if(tmp == NULL){
    olsr_printf("--- MPR Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("---------------\n");

  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];

      olsr_printf("------------ MPR Set ------------\n");
      olsr_printf("%-20s %-16s\n", "local_iface_addr", "MPR_if_addr");
      olsr_printf("---------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET, &data->local_iface_addr.v4, str1, sizeof(str1));
    //inet_ntop(AF_INET, &data->MPR_if_addr.v4, str2, sizeof(str2));
    ConvertIpv4AddressToString(data->local_iface_addr.v4, str1);
    ConvertIpv4AddressToString(data->MPR_if_addr.v4, str2);
    olsr_printf("%-20s %-16s\n", str1, str2);

    tmp = tmp->next;
      }

      olsr_printf("---------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];

      olsr_printf("--------------------------- MPR Set ---------------------------\n");
      olsr_printf("%-46s %-46s\n", "local_iface_addr", "MPR_if_addr");
      olsr_printf("---------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_MPR_TUPLE *)tmp->data;
    //inet_ntop(AF_INET6,
    //    data->local_iface_addr.v6.s6_addr, str1, sizeof(str1));
    //inet_ntop(AF_INET6,
    //    data->MPR_if_addr.v6.s6_addr, str2, sizeof(str2));
    ConvertIpv6AddressToString(&data->local_iface_addr.v6, str1, (olsr_bool)false);
    ConvertIpv6AddressToString(&data->MPR_if_addr.v6, str2, (olsr_bool)false);
    olsr_printf("%-46s %-46s\n", str1, str2);
    tmp = tmp->next;
      }

      olsr_printf("---------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}
}
