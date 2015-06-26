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
#include "mp_olsr_protocol.h"

#include "mp_proc_routing_set.h"
#include "mp_proc_link_set.h"

#include "mp_proc_2neigh_set.h"
#include "mp_proc_topology_set.h"
#include "mp_proc_mpr_set.h"
#include "mp_olsr_util.h"
#include "mp_proc_neighbor_address_association_set.h"
#include "mp_olsr_util_inline.h"
#include "mp_parse_address.h"
/* static function prototypes */
namespace MPOLSRv2{


static
void copy_routing_set(OLSR_LIST *, OLSR_LIST *);

static
void delete_routing_set_for_all_entry(struct olsrv2 *, OLSR_LIST *);
static
OLSR_LIST *search_routing_set_for_dest(struct olsrv2 *, union olsr_ip_addr *);
static
olsr_bool search_routing_set_for_dest_exist(struct olsrv2 *, union olsr_ip_addr *);
static
OLSR_LIST *search_routing_set_for_dest(struct olsrv2 *, union olsr_ip_addr *);

static
olsr_bool delete_routing_set_for_all_entry_handler(void*, void *, void *);
static
olsr_bool search_routing_set_for_dest_handler(void*, void *, void *);


static
olsr_bool search_routing_set_for_next_and_dest_handler(void*, void *, void *);


static
olsr_bool delete_routing_set_old_handler(void *olsr, void *arg_a, void *arg_b);

static
olsr_bool match_local_iface_addr(void *olsr, union olsr_ip_addr *);


/* function implimentations */
void init_routing_set(struct olsrv2 *olsr)
{
  OLSR_InitHashList(&olsr->routing_set[0]);
  OLSR_InitHashList(&olsr->routing_set_new[0]);
  OLSR_InitHashList(&olsr->routing_set_old[0]);
}

olsr_bool check_recalculate_routing_set(struct olsrv2 *olsr)
{
    return (olsr_bool)(olsr->change_link_set      ||
               olsr->change_associ_set    ||
               olsr->change_two_neigh_set ||
               olsr->change_topology_set  ||
               olsr->change_attached_set);
}

void reset_recalculate_routing_set(struct olsrv2 *olsr)
{
    olsr->change_link_set = olsr->change_associ_set =
    olsr->change_two_neigh_set = olsr->change_topology_set = OLSR_FALSE;
}

void proc_routing_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp_A = NULL, *tmp_B = NULL;

  OLSR_LINK_TUPLE *link_data = NULL, *link_data_2hop = NULL;
  OLSR_2NEIGH_TUPLE *two_nei_data = NULL;
  //OLSR_ASSOCI_TUPLE *associ_data;
  OLSR_ASSOCIATION_TUPLE *associ_data = NULL, *list_data = NULL;
  OLSR_TOPOLOGY_TUPLE *topology_data = NULL;
  OLSR_ROUTING_TUPLE *routing_data = NULL;
  olsr_u8_t default_prefix;
  olsr_u32_t index;
  int i;

  OLSR_LIST *retList = NULL, *link_retList = NULL;

  olsr_time_t time;
  int hash_index;

  int h;
  olsr_bool insert;;

  get_current_time(olsr, &time);
  // block signals until routing calcuration is finished
  if(olsr->olsr_cnf->ip_version == AF_INET)
  {
      default_prefix = 32;
  }else
  {
      default_prefix = 128;
  }


  //14
  //14.1

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
  {
      delete_routing_set_for_all_entry(olsr, &olsr->routing_set[hash_index].list);
  }

  //14.2
  tmp_A = olsr->link_set.head;

  while(tmp_A)
  {
      link_data = (OLSR_LINK_TUPLE *)tmp_A->data;
      if(get_link_status(time,
             link_data->L_SYM_time,
             link_data->L_ASYM_time,
             link_data->L_LOST_LINK_time) == SYMMETRIC)
      {
      if(DEBUG_OLSRV2)
      {
          olsr_printf("------call insert_routing_set---------\n");
      }
      insert_routing_set(olsr,
                 &link_data->L_neighbor_iface_addr,
                 &link_data->L_neighbor_iface_addr,
                 default_prefix,
                 1,
                 &link_data->L_local_iface_addr);

      }

      tmp_A = tmp_A->next;
  }

  //14.3 (XXX)
  // for each neighbor address association tuple, for which two
  // addresses A1 and A2 exist in I_neighbor_iface_addr_list where:

  for(index=0; index < HASHSIZE; index++)
  {
      union olsr_ip_addr A_addr, B_addr;

      tmp_A = olsr->associ_set[index].list.head;
      while(tmp_A)
      {
      associ_data = (OLSR_ASSOCIATION_TUPLE *)tmp_A->data;
      olsr_ip_copy(olsr, &A_addr, &associ_data->NA_iface_addr);

      for(i = 0; i < associ_data->num_NAlist; i++)
      {
          tmp_B = associ_data->NA_list[i];
          list_data = (OLSR_ASSOCIATION_TUPLE *)tmp_B->data;
          olsr_ip_copy(olsr, &B_addr, &list_data->NA_iface_addr);

          if(!equal_ip_addr(olsr, &A_addr, &B_addr))
          {
          retList = search_routing_set_for_dest(olsr, &A_addr);

          if(retList != NULL)
          {
              routing_data = (OLSR_ROUTING_TUPLE *)retList->head->data;
              OLSR_DeleteList_Search(retList);

              insert_routing_set(olsr,
                     &B_addr,
                     &routing_data->R_next_iface_addr,
                     default_prefix,
                     routing_data->R_dist,
                     &routing_data->R_iface_addr);
              assert(routing_data->R_dist == 1);
          }
          }
      }
      tmp_A = tmp_A->next;
      }
  }

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
  {
      tmp_A = olsr->routing_set[hash_index].list.head;

      while(tmp_A)
      {
      routing_data = (OLSR_ROUTING_TUPLE *)tmp_A->data;
      retList = search_2neigh_set_for_mpr_n(olsr,
                        &routing_data->R_iface_addr,
                        &routing_data->R_next_iface_addr);
      if(retList)
      {
          tmp_B = retList->head;
          while(tmp_B)
          {
          two_nei_data = (OLSR_2NEIGH_TUPLE *)tmp_B->data;
          link_retList = search_link_set(olsr,
                         &two_nei_data->N2_2hop_iface_addr);
          if(link_retList)
          {
              link_data_2hop = (OLSR_LINK_TUPLE *)link_retList->head->data;
              OLSR_DeleteList_Search(link_retList);
              if(get_link_status(
                 time,
                 link_data_2hop->L_SYM_time,
                 link_data_2hop->L_ASYM_time,
                 link_data_2hop->L_LOST_LINK_time) == SYMMETRIC)
              {
              tmp_B = tmp_B->next;
              continue;
              }
          }

          insert_routing_set(olsr,
                     &two_nei_data->N2_2hop_iface_addr,
                     &routing_data->R_next_iface_addr,
                     default_prefix,
                     2,
                     &routing_data->R_iface_addr);

          tmp_B = tmp_B->next;
          }
          OLSR_DeleteList_Search(retList);
      }
      tmp_A = tmp_A->next;
      }
  }

  //14.5
  //14.5.1

  h = 2;
  insert = OLSR_TRUE;

  while(insert == OLSR_TRUE)
  {
      insert = OLSR_FALSE;

      for(hash_index = 0; hash_index  < HASHSIZE; hash_index++)
      {
      tmp_A = olsr->routing_set[hash_index].list.head;

      while(tmp_A)
      {
          routing_data = (OLSR_ROUTING_TUPLE *)tmp_A->data;

          tmp_A = tmp_A->next;

          if(routing_data->R_dist != h)
          {
          continue;
          }

          retList = search_topology_set_for_last(olsr, &routing_data->R_dest_iface_addr);

          if(retList)
          {
          tmp_B = retList->head;
          while(tmp_B)
          {
              topology_data = (OLSR_TOPOLOGY_TUPLE *)tmp_B->data;

              if(search_routing_set_for_dest_exist(
                 olsr, &topology_data->T_dest_iface_addr) == OLSR_FALSE)
              {
              insert_routing_set(olsr,
                         &topology_data->T_dest_iface_addr,
                         &routing_data->R_next_iface_addr,
                         default_prefix,
                         routing_data->R_dist+1,
                         &routing_data->R_iface_addr);
              insert = OLSR_TRUE;
              }
              tmp_B = tmp_B->next;
          }
          OLSR_DeleteList_Search(retList);
          }
      }//while
      }//for

      h++;
  }
  //14.5.2

}

void insert_routing_set(struct olsrv2 *olsr,
            union olsr_ip_addr *dest_iface_addr,
            const union olsr_ip_addr *next_iface_addr,
            olsr_u8_t prefix_length,
            olsr_u16_t dist,
            const union olsr_ip_addr *iface_addr)
{
  OLSR_ROUTING_TUPLE data;

  //Multi path check
  if(OLSR_TRUE)
  {
    if(search_routing_set_for_dest_exist(olsr, dest_iface_addr) == OLSR_TRUE ||//yowada add
       match_local_iface_addr(olsr, dest_iface_addr) == OLSR_TRUE)
      {
      if(DEBUG_OLSRV2)
      {
          char* paddr = olsr_niigata_ip_to_string(olsr, dest_iface_addr);
          olsr_printf("Route %s has already exist! hopcount = %d\n",paddr,dist);
          free(paddr);
      }

      return;
      //olsr_error("Multi path!!\n");
      }
  }
//Fix for Solaris
  //data.R_dest_iface_addr = *dest_iface_addr;
  //data.R_next_iface_addr = *next_iface_addr;
  olsr_ip_copy(olsr, &data.R_dest_iface_addr, dest_iface_addr);
  olsr_ip_copy(olsr, &data.R_next_iface_addr, next_iface_addr);
  data.R_prefix_length = prefix_length;
  data.R_dist = dist;
  //data.R_iface_addr = *iface_addr;
  olsr_ip_copy(olsr, &data.R_iface_addr, iface_addr);

  /*
    assert(equal_ip_addr(olsr_cnf->ip_version,
    data.R_dest_iface_addr,
    data.R_iface_addr) == OLSR_FALSE);
  */
  if(equal_ip_addr(olsr,
           &data.R_dest_iface_addr,
           &data.R_iface_addr))
  {
      return;
  }

  OLSR_InsertList(&olsr->routing_set[olsr_hashing(olsr,&data.R_dest_iface_addr)].list,
          &data, sizeof(OLSR_ROUTING_TUPLE));
  /*   OLSR_InsertList_Sort(&olsr->routing_set, */
  /*               &data, */
  /*               sizeof(OLSR_ROUTING_TUPLE), */
  /*               sort_routing_set_handler); */
}


void insert_routing_set_old(struct olsrv2 *olsr,
                const union olsr_ip_addr *dest_iface_addr,
                const union olsr_ip_addr *next_iface_addr,
                olsr_u8_t prefix_length,
                olsr_u16_t dist,
                const union olsr_ip_addr *iface_addr)
{
  OLSR_ROUTING_TUPLE data;
//Fix for Solaris
  //data.R_dest_iface_addr = *dest_iface_addr;
  //data.R_next_iface_addr = *next_iface_addr;
  olsr_ip_copy(olsr, &data.R_dest_iface_addr, dest_iface_addr);
  olsr_ip_copy(olsr, &data.R_next_iface_addr, next_iface_addr);
  data.R_prefix_length = prefix_length;
  data.R_dist = dist;
  //data.R_iface_addr = *iface_addr;
  olsr_ip_copy(olsr, &data.R_iface_addr, iface_addr);

  OLSR_InsertList(&olsr->routing_set_old[olsr_hashing(olsr,&data.R_dest_iface_addr)].list,
          &data, sizeof(OLSR_ROUTING_TUPLE));
}


void delete_routing_set_old(struct olsrv2 *olsr,
                union olsr_ip_addr *dest_iface_addr,
                const union olsr_ip_addr *next_iface_addr)
{
  OLSR_ROUTING_TUPLE todelete;

  olsr_ip_copy(olsr, &todelete.R_dest_iface_addr, dest_iface_addr);
  olsr_ip_copy(olsr, &todelete.R_next_iface_addr, next_iface_addr);

  OLSR_DeleteListHandler((void*)olsr,
             &olsr->routing_set_old[olsr_hashing(olsr,dest_iface_addr)].list,
             (void* )&todelete,
             &delete_routing_set_old_handler);
}

olsr_bool delete_routing_set_old_handler(void *olsr,
                     void *arg_a,
                     void *arg_b)
{
  OLSR_ROUTING_TUPLE *data = NULL, *param = NULL;


  data = (OLSR_ROUTING_TUPLE *)arg_a;
  param = (OLSR_ROUTING_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->R_dest_iface_addr,
                   &param->R_dest_iface_addr) &&
             equal_ip_addr((struct olsrv2* )olsr,
                   &data->R_next_iface_addr,
                   &param->R_next_iface_addr));

}



void copy_routing_set(OLSR_LIST *to, OLSR_LIST *from)
{
  OLSR_CopyList(to, from);
}

void delete_routing_set_for_all_entry(struct olsrv2* olsr, OLSR_LIST *list)
{
  OLSR_DeleteListHandler((void*)olsr,list, NULL,
             &delete_routing_set_for_all_entry_handler);
}

olsr_bool delete_routing_set_for_all_entry_handler(void *olsr, void *arg_a, void *arg_b)
{
  return OLSR_TRUE;
}

olsr_bool search_routing_set_for_dest_exist(struct olsrv2 *olsr,
                        union olsr_ip_addr *addr)
{
  return OLSR_CheckMatchExist((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,addr)].list,
                  (void* )addr,
                  &search_routing_set_for_dest_handler);
}
OLSR_LIST *search_routing_set_for_dest(struct olsrv2 *olsr,
                       union olsr_ip_addr *addr)
{
  return OLSR_SearchList((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,addr)].list,
             (void* )addr,
             &search_routing_set_for_dest_handler);
}

olsr_bool search_routing_set_for_dest_handler(void *olsr, void *arg_a, void *arg_b)
{
  OLSR_ROUTING_TUPLE *data = NULL;
  union olsr_ip_addr *addr = NULL;

  data = (OLSR_ROUTING_TUPLE *)arg_a;
  addr = (union olsr_ip_addr *)arg_b;

  return (olsr_bool)equal_ip_addr((struct olsrv2* )olsr,
                  &data->R_dest_iface_addr,
                  addr);
}

OLSR_LIST *search_routing_set_for_next_and_dest(
                        struct olsrv2* olsr,
                        union olsr_ip_addr *dest_iface_addr,
                        const union olsr_ip_addr *next_iface_addr)
{
  OLSR_LIST *result = NULL;
  OLSR_ROUTING_TUPLE search;

  olsr_ip_copy(olsr, &search.R_dest_iface_addr, dest_iface_addr);
  olsr_ip_copy(olsr, &search.R_next_iface_addr, next_iface_addr);

  result = OLSR_SearchList((void*)olsr,&olsr->routing_set[olsr_hashing(olsr,dest_iface_addr)].list,
               (void* )&search,
               &search_routing_set_for_next_and_dest_handler);

  return result;

}

OLSR_LIST *search_routing_set_old_for_next_and_dest(
                            struct olsrv2* olsr,
                            union olsr_ip_addr *dest_iface_addr,
                            const union olsr_ip_addr *next_iface_addr)
{
  OLSR_LIST *result = NULL;
  OLSR_ROUTING_TUPLE search;

  olsr_ip_copy(olsr, &search.R_dest_iface_addr, dest_iface_addr);
  olsr_ip_copy(olsr, &search.R_next_iface_addr, next_iface_addr);

  result = OLSR_SearchList((void*)olsr,&olsr->routing_set_old[olsr_hashing(olsr,dest_iface_addr)].list,
               (void* )&search,
               &search_routing_set_for_next_and_dest_handler);

  return result;

}


olsr_bool search_routing_set_for_next_and_dest_handler(void* olsr,
                               void *arg_a,
                               void *arg_b)
{
  OLSR_ROUTING_TUPLE *data = NULL, *param = NULL;


  data = (OLSR_ROUTING_TUPLE *)arg_a;
  param = (OLSR_ROUTING_TUPLE *)arg_b;

  return (olsr_bool)(equal_ip_addr((struct olsrv2* )olsr,
                   &data->R_dest_iface_addr,
                   &param->R_dest_iface_addr) &&
             equal_ip_addr((struct olsrv2* )olsr,
                   &data->R_next_iface_addr,
                   &param->R_next_iface_addr));

}

void print_routing_set(struct olsrv2 *olsr)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ROUTING_TUPLE *data = NULL;
  int i;

  if(olsr->olsr_cnf->debug_level < 2)
    return;

  olsr_printf("--- Routing Set ---\n");
  olsr_printf("%-17s %-17s %-12s %-16s %-10s\n",
     "R_dest_iface_addr", "R_next_iface_addr", "R_dist", "R_iface_addr", "R_prefix");
  for(i=0; i<HASHSIZE; i++)
  {
      tmp = olsr->routing_set[i].list.head;
      if(tmp == NULL){

      }else{
      if(olsr->olsr_cnf->ip_version == AF_INET){
          char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN], str3[INET_ADDRSTRLEN];

          while(tmp){
          data = (OLSR_ROUTING_TUPLE *)tmp->data;
          //WIN FIX: Need to resolve this
          //inet_ntop(AF_INET, &data->R_dest_iface_addr.v4, str1, sizeof(str1));
          //inet_ntop(AF_INET, &data->R_next_iface_addr.v4, str2, sizeof(str2));
          //inet_ntop(AF_INET, &data->R_iface_addr.v4, str3, sizeof(str3));
          ConvertIpv4AddressToString(data->R_dest_iface_addr.v4, str1);
          ConvertIpv4AddressToString(data->R_next_iface_addr.v4, str2);
          ConvertIpv4AddressToString(data->R_iface_addr.v4, str3);


          olsr_printf("%-17s %-17s %-12d %-16s %-10d\n",
             str1,
             str2,
             data->R_dist,
             str3,
             data->R_prefix_length);
          tmp = tmp->next;
          }

      }

      else if(olsr->olsr_cnf->ip_version == AF_INET6){
          char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN], str3[INET6_ADDRSTRLEN];

          olsr_printf("%-46s %-46s %-12s %-46s %-10s\n",
             "R_dest_iface_addr", "R_next_iface_addr", "R_dist", "R_iface_addr", "R_prefix");
          while(tmp){
          data = (OLSR_ROUTING_TUPLE *)tmp->data;
          //WIN FIX: Need to resolve this
          //inet_ntop(AF_INET6, data->R_dest_iface_addr.v6.s6_addr, str1, sizeof(str1));
          //inet_ntop(AF_INET6, data->R_next_iface_addr.v6.s6_addr, str2, sizeof(str2));
          //inet_ntop(AF_INET6, data->R_iface_addr.v6.s6_addr, str3, sizeof(str3));
          ConvertIpv6AddressToString(&data->R_dest_iface_addr.v6, str1, OLSR_FALSE);
          ConvertIpv6AddressToString(&data->R_next_iface_addr.v6, str2, OLSR_FALSE);
          ConvertIpv6AddressToString(&data->R_iface_addr.v6, str3, OLSR_FALSE);


          olsr_printf("%-46s %-46s %-12d %-46s %-10d\n",
             str1,
             str2,
             data->R_dist,
             str3,
             data->R_prefix_length);
          tmp = tmp->next;
          }

      }

      else{
          olsr_error("Un known ip_version");
          assert(OLSR_FALSE);
      }
      }


  }
  olsr_printf("-------------------\n");
}


//yowada
olsr_bool match_local_iface_addr(void *olsr, olsr_ip_addr *neigh_addr)
{
  struct olsrv2* olsr1 = (struct olsrv2* ) olsr;
  union olsr_ip_addr *local_addr = NULL;
  int ifnum,i;
  ifnum = ((struct olsrv2 *)olsr)->iface_num;
  for(i=0; i < ifnum; i++){
    local_addr = &((struct olsrv2 *)olsr)->iface_addr[i];
  if(DEBUG_OLSRV2)
  {
    if(olsr1->olsr_cnf->ip_version == AF_INET)
    {
      char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];
      ConvertIpv4AddressToString(local_addr->v4, str1);
      ConvertIpv4AddressToString(neigh_addr->v4, str2);
      olsr_printf("Local addr %s,\tNeigh addr %s\n",str1, str2);
    }
    else if(olsr1->olsr_cnf->ip_version == AF_INET6)
    {
      char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];
      ConvertIpv6AddressToString(&local_addr->v6, str1, OLSR_FALSE);
      ConvertIpv6AddressToString(&neigh_addr->v6, str2, OLSR_FALSE);
      olsr_printf("Local addr %s,\tNeigh addr %s\n",str1, str2);
    }
  }
  if(equal_ip_addr((struct olsrv2 *)olsr, neigh_addr ,local_addr) == OLSR_TRUE)
      return OLSR_TRUE;
  }
  return OLSR_FALSE;
}
}
