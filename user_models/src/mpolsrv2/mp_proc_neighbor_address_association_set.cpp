
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
#include "mp_def.h"
#include "mp_proc_neighbor_address_association_set.h"


#include "mp_olsr_debug.h"
#include "mp_olsr_util.h"
#include "mp_olsr_hash_list.h"
#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

static void delete_association_set_for_addr(struct olsrv2 *,
                        OLSR_LIST *);
static void insert_association_set(struct olsrv2 *,
                   OLSR_LIST *,
                   double);
static OLSR_LIST *search_association_set_for_addr(struct olsrv2 *,
                          union olsr_ip_addr *);
static olsr_bool search_association_set_for_addr_handler(void* olsr,
                             void *arg_a,
                             void *arg_b);



void init_association_set(struct olsrv2 *olsr){
  olsr->change_associ_set = OLSR_FALSE;
  OLSR_InitHashList(olsr->associ_set);
}

OLSR_LIST *search_association_set_for_addr(struct olsrv2 *olsr,
                       union olsr_ip_addr *addr){
  OLSR_ASSOCIATION_TUPLE search;

  olsr_ip_copy(olsr, &search.NA_iface_addr, addr);
  return OLSR_SearchList((void*)olsr,
             &olsr->associ_set[olsr_hashing(olsr,addr)].list,
             (void* )&search,
             &search_association_set_for_addr_handler);
}

olsr_bool search_association_set_for_addr_exist(struct olsrv2 *olsr,
                        union olsr_ip_addr *addr){
    OLSR_ASSOCIATION_TUPLE search;

    olsr_ip_copy(olsr, &search.NA_iface_addr, addr);
    return OLSR_CheckMatchExist((void*)olsr,
                &olsr->associ_set[olsr_hashing(olsr,addr)].list,
                (void* )&search,
                &search_association_set_for_addr_handler);
}

olsr_bool search_association_set_for_addr_handler(void* olsr,
                          void *arg_a, void *arg_b){
  OLSR_ASSOCIATION_TUPLE *data = NULL, *param = NULL;

  data = (OLSR_ASSOCIATION_TUPLE *)arg_a;
  param = (OLSR_ASSOCIATION_TUPLE *)arg_b;

  return (olsr_bool)equal_ip_addr((struct olsrv2* )olsr,
                  &data->NA_iface_addr,
                  &param->NA_iface_addr);
}

olsr_bool delete_association_set_for_addr_handler(void* olsr, void *arg_a, void *arg_b){

  olsr_ip_addr *data = NULL, *param = NULL;

  data = (olsr_ip_addr *)arg_a;
  param = (olsr_ip_addr *)arg_b;
  return (olsr_bool)equal_ip_addr((struct olsrv2* )olsr,
                  data,
                  param);

}

void delete_association_set_for_addr(struct olsrv2 *olsr,
                     OLSR_LIST *iface_list){
  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *local_iface_data = NULL;
  OLSR_ASSOCIATION_TUPLE *associ_data = NULL, *associ_list_data = NULL;
  OLSR_LIST *retList = NULL;
  OLSR_LIST_ENTRY *entry = NULL,*list_entry = NULL;
  int i, tmp_index;

  entry = iface_list->head;
  while(entry){
    local_iface_data = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)entry->data;
    retList = search_association_set_for_addr(olsr,
                          &local_iface_data->iface_addr);

    if(retList){
      if(retList->numEntry != 1){
    olsr_error("delete_association_set_for_addr");
      }

      associ_data = (OLSR_ASSOCIATION_TUPLE *)retList->head->data;
      OLSR_DeleteList_Search(retList);

      for(i = 0; i < associ_data->num_NAlist; i++) {
    list_entry = (OLSR_LIST_ENTRY *)associ_data->NA_list[i];
    associ_list_data = (OLSR_ASSOCIATION_TUPLE *)list_entry->data;
    tmp_index = olsr_hashing(olsr,&associ_list_data->NA_iface_addr);
    free(associ_list_data->NA_list);
    OLSR_DeleteListEntry(&olsr->associ_set[tmp_index].list, list_entry);
      }
      free(associ_data->NA_list);
      if(OLSR_DeleteListHandler((void* )olsr,
                &olsr->associ_set[olsr_hashing(olsr,&associ_data->NA_iface_addr)].list,
                (void* )&local_iface_data->iface_addr,
                &delete_association_set_for_addr_handler)){

    olsr->change_associ_set = OLSR_TRUE;
      }

    }//if
    entry = entry->next;
  }//while

}


void insert_association_set(struct olsrv2 *olsr,
                OLSR_LIST *iface_list,
                double validity_time){

  OLSR_LIST_ENTRY **entry = NULL, *iface_entry = NULL;
  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *local_iface_data = NULL;
  int i,j, seq, listNum;
  OLSR_ASSOCIATION_TUPLE *data = NULL;

  listNum = iface_list->numEntry;
  entry = (OLSR_LIST_ENTRY **)olsr_malloc(listNum * sizeof(OLSR_LIST_ENTRY *),
                      __FUNCTION__);
  for(i = 0; i < listNum; i++) {
    entry[i] = (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY),
                          __FUNCTION__);
    entry[i]->data =
      (OLSR_ASSOCIATION_TUPLE *)olsr_malloc(sizeof(OLSR_ASSOCIATION_TUPLE),
                        __FUNCTION__);
    entry[i]->size = sizeof(OLSR_ASSOCIATION_TUPLE);
  }

  iface_entry = iface_list->head;
  i = 0;
  while(iface_entry) {

    local_iface_data = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)iface_entry->data;
    data = (OLSR_ASSOCIATION_TUPLE *)entry[i]->data;

    get_current_time(olsr, &data->NA_time);
    update_time(&data->NA_time, (olsr_32_t)validity_time);
    olsr_ip_copy(olsr, &data->NA_iface_addr, &local_iface_data->iface_addr);
    data->num_NAlist = listNum -1;
    data->NA_list =
      (OLSR_LIST_ENTRY **)olsr_malloc(sizeof(OLSR_LIST_ENTRY*) * (listNum-1),
                      __FUNCTION__);

    seq = 0;
    for(j = 0; j < listNum; j++) {
      if(i == j)
    continue;
      data->NA_list[seq++] = entry[j];
    }

    OLSR_InsertListEntry(&olsr->associ_set[olsr_hashing(olsr,&data->NA_iface_addr)].list,
             entry[i]);

    iface_entry = iface_entry->next;
    i++;
  }

  free(entry);

}

void delete_association_set_for_timeout(struct olsrv2 *olsr){
  OLSR_LIST_ENTRY *entry = NULL, *list_entry = NULL, *del = NULL;
  OLSR_ASSOCIATION_TUPLE *data = NULL, *list_data = NULL;
  int hash_index, i;
  olsr_time_t time;

  //return;
  //  olsr_cnf->debug_level = 9;
  //print_association_set(olsr);
  //olsr_cnf->debug_level = 0;

  get_current_time(olsr, &time);
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++) {
    entry = olsr->associ_set[hash_index].list.head;
      while(entry) {

      data = (OLSR_ASSOCIATION_TUPLE *)entry->data;
      del = entry;
      entry = entry->next;

      if(olsr_cmp_time(data->NA_time, time) < 0) {
    for(i = 0; i < data->num_NAlist; i++) {
      list_entry = data->NA_list[i];
      list_data = (OLSR_ASSOCIATION_TUPLE *)list_entry->data;

      if(list_entry == entry) {
        entry = entry->next;
      }
      free(list_data->NA_list);
      OLSR_DeleteListEntry(&olsr->associ_set[olsr_hashing(olsr, &list_data->NA_iface_addr)].list,
                   list_entry);

    }
    free(data->NA_list);
    OLSR_DeleteListEntry(&olsr->associ_set[olsr_hashing(olsr, &data->NA_iface_addr)].list,
                 del);

    olsr->change_associ_set = OLSR_TRUE;
      }
    }

  }
}

void proc_association_set(struct olsrv2 *olsr,
              OLSR_LIST *iface_list, double validity_time){
  delete_association_set_for_addr(olsr, iface_list);
  insert_association_set(olsr, iface_list, validity_time);
/*   olsr_cnf->debug_level = 9; */
/*   print_association_set(olsr); */
/*   olsr_cnf->debug_level = 0; */
}

void print_association_set(struct olsrv2 *olsr){
  int hash_index;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_ASSOCIATION_TUPLE *data = NULL;
  olsr_bool put_head = OLSR_FALSE;

  if(olsr->olsr_cnf->debug_level < 2)
    return;
  for(hash_index = 0; hash_index < HASHSIZE; hash_index++) {
    entry = olsr->associ_set[hash_index].list.head;
    while(entry) {
      if(put_head == OLSR_FALSE){
    put_head = OLSR_TRUE;

    olsr_printf("----------------------------------------- NEIGHBOR ADDRESS ASSOCIATION SET ---------------------------------------\n");
    if(olsr->olsr_cnf->ip_version == AF_INET) {
      olsr_printf("%-25s %-20s %-25s\n",
         "NA_iface_addr", "NA_time", "NA_iface_list");
    } else {
      olsr_printf("%-46s %-20s %-46s\n",
         "NA_iface_addr", "NA_time", "NA_iface_list");
    }
      }

      data = (OLSR_ASSOCIATION_TUPLE *)entry->data;
      if(olsr->olsr_cnf->ip_version == AF_INET) {
    char str1[INET_ADDRSTRLEN];

    //WIN FIX: Need to resolve this
    //inet_ntop(AF_INET, &data->NA_iface_addr.v4, str1, sizeof(str1));
    ConvertIpv4AddressToString(data->NA_iface_addr.v4, str1);

    char time[30];
    qualnet_print_clock_in_second(data->NA_time, time);
    olsr_printf("%-25s(%u) %s     ",str1, hash_index,  time);
    char str2[INET_ADDRSTRLEN];
    int list_num;
    OLSR_ASSOCIATION_TUPLE *list_data;
    for(list_num = 0; list_num < data->num_NAlist; list_num++) {
      list_data = (OLSR_ASSOCIATION_TUPLE *)data->NA_list[list_num]->data;

      //WIN FIX: Need to resolve this
      //inet_ntop(AF_INET, &data->NA_iface_addr.v4, str1, sizeof(str1));
      ConvertIpv4AddressToString(list_data->NA_iface_addr.v4, str2);

      olsr_printf("%s ", str2);
    }
    olsr_printf("\n");
      } else {
    ;;//ipv6
      }
      entry = entry->next;
    }

  }//for

  if(put_head == OLSR_FALSE) {
    olsr_printf("---------------------- NEIGHBOR ADDRESS ASSOCIATION SET -------------------\n");
    olsr_printf("\t\t\t\tno entry.\n");
  }
  olsr_printf("\n");
}
}
