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

#include "mp_olsr_conf.h"
#include "mp_def.h"
#include "mp_olsr_debug.h"
#include "mp_proc_relay_set.h"
#include "mp_proc_mpr_selector_set.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

/* static function prototypes */
static
void insert_relay_set(struct olsrv2 *,
          union olsr_ip_addr *);

static
olsr_bool delete_relay_set_handler(void *, void *, void *);



static
olsr_bool search_relay_set_handler(void *, void *, void *);


/* function implimentations */
void init_relay_set(struct olsrv2 *olsr)
{
  olsr->change_relay_set = OLSR_FALSE;
  OLSR_InitList(&olsr->relay_set);
}

olsr_u16_t
get_local_assn(struct olsrv2 *olsr)
{
  return olsr->assn;
}

void
increment_local_assn(struct olsrv2 *olsr)
{
  olsr->assn++;
}

olsr_bool proc_relay_set(struct olsrv2 *olsr,
                 union olsr_ip_addr *neighbor_iface_addr)
{
  //12.1

  if(search_relay_set_for_exist(olsr, neighbor_iface_addr) == OLSR_FALSE){
    insert_relay_set(olsr, neighbor_iface_addr);
    olsr->change_relay_set = OLSR_TRUE;
    return OLSR_TRUE;
  }else{
    return OLSR_FALSE;
  }
}

void insert_relay_set(struct olsrv2 *olsr,
              union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_RELAY_TUPLE data;
//Fix for Solaris
  //data.RS_if_addr = *neighbor_iface_addr;
  olsr_ip_copy(olsr, &data.RS_if_addr, neighbor_iface_addr);
  OLSR_InsertList(&olsr->relay_set, &data, sizeof(OLSR_RELAY_TUPLE));
}


void delete_relay_set(struct olsrv2 *olsr,
              union olsr_ip_addr *neighbor_iface_addr)
{

  if(OLSR_DeleteListHandler((void*)olsr,&olsr->relay_set,
                (void* )neighbor_iface_addr,
                &delete_relay_set_handler))
  {
      olsr->change_relay_set = OLSR_TRUE;
  }
}



olsr_bool delete_relay_set_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_RELAY_TUPLE *data = NULL;
  union olsr_ip_addr *neighbor_iface_addr;

  data = (OLSR_RELAY_TUPLE *)arg_a;
  neighbor_iface_addr = (union olsr_ip_addr *)arg_b;
  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr, &data->RS_if_addr,
            neighbor_iface_addr));
}



OLSR_LIST *
search_relay_set(struct olsrv2 *olsr,
             union olsr_ip_addr *neighbor_iface_addr)
{
  OLSR_LIST *result = NULL;

  result = OLSR_SearchList((void*)olsr,&olsr->relay_set,
               (void* )neighbor_iface_addr, &search_relay_set_handler);

  return result;
}

olsr_bool search_relay_set_for_exist(struct olsrv2 *olsr,
                     union olsr_ip_addr *neighbor_iface_addr)
{
  return OLSR_CheckMatchExist((void*)olsr,&olsr->relay_set,
                  neighbor_iface_addr, &search_relay_set_handler);
}

int check_relay_set_for_match_num_entry(struct olsrv2 *olsr,
                    union olsr_ip_addr *neighbor_iface_addr)
{
  return OLSR_CheckMatchEntryNum((void*)olsr,&olsr->relay_set,
                 (void* )neighbor_iface_addr, &search_relay_set_handler);
}


void delete_relay_set_handler_for_ms_timeout(struct olsrv2 *olsr,
                         OLSR_LIST* retList)
{
  OLSR_LIST_ENTRY* ms_tmp = NULL;
  OLSR_MPR_SELECTOR_TUPLE* ms_data = NULL;
  OLSR_LIST *result = NULL;

  ms_tmp = retList->head;

  while(ms_tmp){
    ms_data = (OLSR_MPR_SELECTOR_TUPLE* )ms_tmp->data;


    result = OLSR_SearchList((void*)olsr,&olsr->relay_set,
                 (void* )&ms_data->MS_neighbor_if_addr,
                 &search_relay_set_handler);

    if(result){
      OLSR_DeleteList_Search(result);
      OLSR_DeleteListHandler((void*)olsr,&olsr->relay_set, (void* )&ms_data->MS_neighbor_if_addr,
                 &delete_relay_set_handler);
      olsr->change_relay_set = OLSR_TRUE;
    }
    ms_tmp = ms_tmp->next;
  }
}

olsr_bool search_relay_set_handler(void *olsr,
                   void *arg_a, void *arg_b)
{
  OLSR_RELAY_TUPLE *data = NULL;
  union olsr_ip_addr *neighbor_iface_addr = NULL;

  data = (OLSR_RELAY_TUPLE *)arg_a;
  neighbor_iface_addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2 *)olsr, &data->RS_if_addr,
               neighbor_iface_addr));
}

void print_relay_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_RELAY_TUPLE *data = NULL;

  if(olsr->olsr_cnf->debug_level < 2)
    return;
  tmp = olsr->relay_set.head;
  if(tmp == NULL){
    olsr_printf("---  Relay Set ---\n");
    olsr_printf("no entry.\n");
    olsr_printf("----------------------------\n");
  }else{
    if(olsr->olsr_cnf->ip_version == AF_INET){
      char str[INET_ADDRSTRLEN];

      olsr_printf("-------------- Relay Neighbor Set --------------\n");
      olsr_printf("%-16s\n", "RS_if_addr");
      olsr_printf("--------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_RELAY_TUPLE *)tmp->data;
    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->RS_if_addr.v4, str, sizeof(str));
    ConvertIpv4AddressToString(data->RS_if_addr.v4, str);

    olsr_printf("%-16s\n", str);
    tmp = tmp->next;
      }

      olsr_printf("--------------------------------------------------\n");
    }

    else if(olsr->olsr_cnf->ip_version == AF_INET6){
      char str[INET6_ADDRSTRLEN];

      olsr_printf("---------------------------- Relay Set ------------------------------\n");
      olsr_printf("%-46s\n", "RS_if_addr");
      olsr_printf("--------------------------------------------------------------------------------\n");
      while(tmp != NULL){
    data = (OLSR_RELAY_TUPLE *)tmp->data;
    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET6, data->RS_if_addr.v6.s6_addr, str, sizeof(str));
    ConvertIpv6AddressToString(&data->RS_if_addr.v6, str, OLSR_FALSE);

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
