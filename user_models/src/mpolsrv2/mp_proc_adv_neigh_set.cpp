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
#include "mp_proc_adv_neigh_set.h"

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
#include "mp_proc_mpr_selector_set.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{


/* static function prototypes */
static
void insert_adv_neigh_set(struct olsrv2 *,
              union olsr_ip_addr *);

static
olsr_bool delete_adv_neigh_set_handler(void*, void *, void *);

static
OLSR_LIST *search_adv_neigh_set(struct olsrv2 *,
                union olsr_ip_addr *);


static
olsr_bool search_adv_neigh_set_handler(void*, void *, void *);


/* function implimentations */
void init_adv_neigh_set(struct olsrv2 *olsr)
{

  olsr->change_adv_neigh_set = OLSR_FALSE;
  OLSR_InitList(&olsr->adv_neigh_set);
}

olsr_bool proc_adv_neigh_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_LIST *retList = NULL;

  //12.2
  retList = search_adv_neigh_set(olsr,
                 neighbor_iface_addr);

  if(retList == NULL){
    insert_adv_neigh_set(olsr, neighbor_iface_addr);
    olsr->change_adv_neigh_set = OLSR_TRUE;
    return OLSR_TRUE;
  }else{
    //don't use
    //delete_adv_neigh_set(olsr, neighbor_iface_addr);
    OLSR_DeleteList_Search(retList);

    return OLSR_FALSE;
  }
}

void insert_adv_neigh_set(struct olsrv2 *olsr,
              union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_ADV_NEI_TUPLE data;

  data.A_neighbor_iface_addr = *neighbor_iface_addr;

  OLSR_InsertList(&olsr->adv_neigh_set, &data, sizeof(OLSR_ADV_NEI_TUPLE));
}

void delete_adv_neigh_set(struct olsrv2 *olsr,
              union olsr_ip_addr* neighbor_iface_addr)
{

  //struct olsrv2
  if(OLSR_DeleteListHandler((void*)olsr,&olsr->adv_neigh_set,
                (void* )neighbor_iface_addr, &delete_adv_neigh_set_handler))
  {
      olsr->change_adv_neigh_set = OLSR_TRUE;
  }
}


olsr_bool delete_adv_neigh_set_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_ADV_NEI_TUPLE *data = NULL;
  union olsr_ip_addr *neighbor_iface_addr = NULL;

  data = (OLSR_ADV_NEI_TUPLE *)arg_a;
  neighbor_iface_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->A_neighbor_iface_addr,
                   neighbor_iface_addr));
}

OLSR_LIST *
search_adv_neigh_set(struct olsrv2 *olsr,
             union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_LIST *result = NULL;

  result = OLSR_SearchList((void*)olsr,&olsr->adv_neigh_set,
               (void* )neighbor_iface_addr,
               &search_adv_neigh_set_handler);

  return result;
}


void delete_adv_neigh_set_handler_for_ms_timeout(struct olsrv2 *olsr,
                         OLSR_LIST* retList)
{
  OLSR_LIST_ENTRY* ms_tmp = NULL;
  OLSR_MPR_SELECTOR_TUPLE* ms_data = NULL;
  OLSR_LIST *result = NULL;

  ms_tmp = retList->head;

  while(ms_tmp){
    ms_data = (OLSR_MPR_SELECTOR_TUPLE* )ms_tmp->data;

    result = OLSR_SearchList((void*)olsr,&olsr->adv_neigh_set,
                 (void* )&ms_data->MS_neighbor_if_addr,
                 &search_adv_neigh_set_handler);

    if(result){
      OLSR_DeleteList_Search(result);
      OLSR_DeleteListHandler((void*)olsr,&olsr->adv_neigh_set,
                 (void* )&ms_data->MS_neighbor_if_addr,
                 &delete_adv_neigh_set_handler);
      olsr->change_adv_neigh_set = OLSR_TRUE;
    }
    ms_tmp = ms_tmp->next;
  }
}

olsr_bool search_adv_neigh_set_handler(void* olsr, void *arg_a, void *arg_b)
{
  OLSR_ADV_NEI_TUPLE *data = NULL;
  union olsr_ip_addr *neighbor_iface_addr = NULL;

  data = (OLSR_ADV_NEI_TUPLE *)arg_a;
  neighbor_iface_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->A_neighbor_iface_addr,
                   neighbor_iface_addr));
}

void print_adv_neigh_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ADV_NEI_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  tmp = olsr->adv_neigh_set.head;
  if(tmp == NULL){
    olsr_printf("--- Advertised Neighbor Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("----------------------------\n");
  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str[INET_ADDRSTRLEN];

      olsr_printf("-------------- Advertised Neighbor Set --------------\n");
      olsr_printf("%-16s\n", "A_neighbor_iface_addr");
      olsr_printf("--------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_ADV_NEI_TUPLE *)tmp->data;
    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->A_neighbor_iface_addr.v4, str, sizeof(str));
    ConvertIpv4AddressToString(data->A_neighbor_iface_addr.v4, str);

    olsr_printf("%-16s\n", str);
    tmp = tmp->next;
      }

      olsr_printf("--------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str[INET6_ADDRSTRLEN];

      olsr_printf("---------------------------- Advertised Neighbor Set ------------------------------\n");
      olsr_printf("%-46s\n", "A_neighbor_iface_addr");
      olsr_printf("--------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_ADV_NEI_TUPLE *)tmp->data;
    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET6, data->A_neighbor_iface_addr.v6.s6_addr, str, sizeof(str));
    ConvertIpv6AddressToString(&data->A_neighbor_iface_addr.v6, str, OLSR_FALSE);


    olsr_printf("%-46s\n", str);
    tmp = tmp->next;
      }

      olsr_printf("--------------------------------------------------------------------------------\n");
    }

    else{
      olsr_error("Un known ip_version");
      assert(OLSR_FALSE);
    }
  }
}
}
