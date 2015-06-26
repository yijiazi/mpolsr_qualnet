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
#include <stdlib.h>

#include "mp_olsr_debug.h"
#include "mp_olsr_list.h"//yowada required?
#include "mp_olsr.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

OLSR_LIST_ENTRY *OLSR_InsertList_NotAlloc(OLSR_LIST *, void *, olsr_u32_t);

static
void OLSR_DeleteListEntry_AvoidData(OLSR_LIST *, OLSR_LIST_ENTRY *);

/* function implimentations */
void OLSR_InitList(OLSR_LIST *list)
{
  list->head = NULL;
  list->tail = NULL;
  list->numEntry = 0;
}

OLSR_LIST_ENTRY *OLSR_InsertListEntry(OLSR_LIST *list,
                      OLSR_LIST_ENTRY *entry)
{
  if(list->head == NULL){
    entry->next = NULL;
    entry->prev = NULL;
    list->head = entry;
    list->tail = list->head;
  }else {
    entry->next = NULL;
    entry->prev = list->tail;
    list->tail->next = entry;
    list->tail = entry;
  }
  list->numEntry++;
  return list->tail;
}



OLSR_LIST_ENTRY *OLSR_InsertList(OLSR_LIST *list,
                 void *data, olsr_u32_t size)
{
  if(list->head == NULL){
    list->head =
      (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY), __FUNCTION__);
    list->head->data = olsr_malloc(size, __FUNCTION__);

    memcpy(list->head->data, data, size);
    list->head->size = size;
    list->head->next = NULL;
    list->head->prev = NULL;

    list->tail = list->head;
  }
  else{
    list->tail->next =
      (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY), __FUNCTION__);
    list->tail->next->data = olsr_malloc(size, __FUNCTION__);

    memcpy(list->tail->next->data, data, size);
    list->tail->next->size = size;
    list->tail->next->next = NULL;
    list->tail->next->prev = list->tail;

    list->tail = list->tail->next;
  }

  list->numEntry++;

  return list->tail;
}

static
void OLSR_LIST_swap(int i, int j, OLSR_LIST_ENTRY* temp_list[])
{
  OLSR_LIST_ENTRY* temp = NULL;

  //swap
  temp = temp_list[i];
  temp_list[i] = temp_list[j];
  temp_list[j] = temp;
}

static
int OLSR_LIST_partition(void* olsr,
            int i, int j,
            OLSR_LIST_ENTRY* temp,
            OLSR_LIST_ENTRY* temp_list[],
            OLSR_LIST_HANDLER handler)
{
  int l, r, k;

  l = i;
  r = j;

  while(1)
    {
      while(l <= j)
    {
      if(handler(olsr, temp->data, temp_list[l]->data) == OLSR_TRUE)
        {
          l++;
        }
      else
        {
          break;
        }
    }

      while(r >= i)
    {
      if(handler(olsr, temp->data, temp_list[r]->data) == OLSR_FALSE)
        {
          r--;
        }
      else
        {
          break;
        }
    }

      if(l <= r)
    {
      OLSR_LIST_swap(l, r, temp_list);
      l++;
      r--;
    }
      else
    {
      break;
    }
    }
  k = l;

  return (k);
}

static
int OLSR_LIST_pivot(void* olsr,
            int i, int j, OLSR_LIST_ENTRY* temp_list[],
            OLSR_LIST_HANDLER handler)
{
  int pv, k;

  k = i+1;

  while(k <= j)
    {
      if(handler(olsr, temp_list[k]->data, temp_list[i]->data) == OLSR_TRUE &&
     handler(olsr, temp_list[i]->data, temp_list[k]->data) == OLSR_TRUE)
    {
      k++;
    }
      else
    {
      break;
    }
    }

  if(k > j)
    {
      pv = -1;
    }
  else if(handler(olsr, temp_list[k]->data, temp_list[i]->data) == OLSR_TRUE)
    {
      pv = i;
    }
  else
    {
      pv = k;
    }

  return (pv);
}


static
void OLSR_LIST_quick_sort(void* olsr,
              int i, int j, OLSR_LIST_ENTRY* temp_list[],
              OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY* temp;
  int pv, k;

  pv = OLSR_LIST_pivot(olsr, i, j, temp_list, handler);

  if(pv != -1)
    {
      temp = temp_list[pv];
      k = OLSR_LIST_partition(olsr, i, j, temp, temp_list, handler);
      OLSR_LIST_quick_sort(olsr, i, k-1, temp_list, handler);
      OLSR_LIST_quick_sort(olsr, k, j, temp_list, handler);
    }

  return;
}

void OLSR_List_sort(void* olsr,
            OLSR_LIST* list, OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY** temp_list = NULL;
  OLSR_LIST_ENTRY* temp = NULL;
  olsr_u32_t  i;

  temp = list->head;

  temp_list = (OLSR_LIST_ENTRY** )olsr_malloc
    (list->numEntry*sizeof(OLSR_LIST_ENTRY*), __FUNCTION__);

  //before
  for(i=0; i<list->numEntry; i++, temp = temp->next)
    {
      temp_list[i] = temp;
    }

  //sorting function
  OLSR_LIST_quick_sort(olsr, 0, list->numEntry-1, temp_list, handler);


  //after
  for(i=0; i<list->numEntry-1; i++)
    {
      temp_list[i]->next = temp_list[i+1];
      temp_list[i+1]->prev = temp_list[i];
    }
  temp_list[0]->prev = NULL;
  temp_list[list->numEntry-1]->next = NULL;

  //tukekae !!!
  list->head = temp_list[0];
  list->tail = temp_list[list->numEntry-1];

  free(temp_list);
}


OLSR_LIST_ENTRY *OLSR_InsertList_Sort(void* olsr,
                      OLSR_LIST *list,
                      void *data, olsr_u32_t size,
                      OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY **tmp = NULL, **tmp_tail = NULL;
  OLSR_LIST_ENTRY *entry = NULL;

  tmp = &(list->head);
  tmp_tail = &(list->tail);

  for(; *tmp; tmp = &((*tmp)->next))
    {
      if(handler(olsr, (*tmp)->data, data))
    {
      break;
    }
    }

  entry = (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY), __FUNCTION__);
  entry->data = olsr_malloc(size, __FUNCTION__);

  entry->size = size;
  memcpy(entry->data, data, size);

  if((*tmp) == NULL)
    {
      //change tail
      entry->prev = (*tmp_tail);
      (*tmp_tail) = entry;
    }
  else
    {
      entry->prev = (*tmp)->prev;
      (*tmp)->prev = entry;
    }

  entry->next = (*tmp);
  (*tmp) = entry;

  list->numEntry++;
  return list->tail;

}



OLSR_LIST_ENTRY *OLSR_InsertList_NotAlloc(OLSR_LIST *list,
                      void *data, olsr_u32_t size)
{
  if(list->head == NULL){
    list->head =
      (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY), __FUNCTION__);
    list->head->data = data; //copy pointer
    list->head->size = size;
    list->head->next = NULL;
    list->head->prev = NULL;

    list->tail = list->head;
  }

  else{
    list->tail->next =
      (OLSR_LIST_ENTRY *)olsr_malloc(sizeof(OLSR_LIST_ENTRY), __FUNCTION__);
    list->tail->next->data = data; //copy pointer
    list->tail->next->size = size;
    list->tail->next->next = NULL;
    list->tail->next->prev = list->tail;

    list->tail = list->tail->next;
  }

  list->numEntry++;

  return list->tail;
}

void OLSR_CopyList(OLSR_LIST *to, OLSR_LIST *from)
{
  OLSR_LIST_ENTRY *tmp = NULL;

  tmp = from->head;
  while(tmp != NULL){
    OLSR_InsertList(to, tmp->data, tmp->size);
    tmp = tmp->next;
  }
}


OLSR_LIST *OLSR_SearchList(void* olsr,
               OLSR_LIST *list, void *search,
               OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_LIST *retList = (OLSR_LIST *)olsr_malloc(sizeof(OLSR_LIST), __FUNCTION__);

  OLSR_InitList(retList);

  tmp = list->head;
  while(tmp != NULL){
    if(handler(olsr, tmp->data, search))
      OLSR_InsertList_NotAlloc(retList, tmp->data, tmp->size);
    tmp = tmp->next;
  }

  if(retList->numEntry == 0){
    free(retList);
    return NULL;

  }else{
    if(retList->numEntry > 1)
    {
    if(DEBUG_OLSRV2)
    {
        olsr_printf("%s: retList->numEntry = %d\n",
           __FUNCTION__, retList->numEntry);
    }
    }
    return retList;
  }
}


olsr_bool OLSR_CheckMatchExist(void* olsr,
                   OLSR_LIST *list, void *search,
                   OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY *tmp = NULL;

  tmp = list->head;
  while(tmp != NULL)
    {
      if(handler(olsr, tmp->data, search))
    return OLSR_TRUE; // found search in list
      tmp = tmp->next;
    }

  return OLSR_FALSE;
}

int OLSR_CheckMatchEntryNum(void* olsr,
                OLSR_LIST *list, void *search,
                OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  int count = 0;

  tmp = list->head;
  while(tmp != NULL)
    {
      if(handler(olsr, tmp->data, search))
    count++;
      tmp = tmp->next;
    }

  return count;
}

void OLSR_DeleteListEntry(OLSR_LIST *list, OLSR_LIST_ENTRY *entry)
{
  assert(entry);
  if(entry->next != NULL)
    entry->next->prev = entry->prev;
  if(entry->prev != NULL)
    entry->prev->next = entry->next;

  if(list->head == entry)
    list->head = entry->next;
  if(list->tail == entry)
    list->tail = entry->prev;


  free(entry->data);
  free(entry);

  list->numEntry--;
}

void OLSR_DeleteListEntry_AvoidData(OLSR_LIST *list, OLSR_LIST_ENTRY *entry)
{
  assert(entry);
  if(entry->next != NULL)
    entry->next->prev = entry->prev;
  if(entry->prev != NULL)
    entry->prev->next = entry->next;

  if(list->head == entry)
    list->head = entry->next;
  if(list->tail == entry)
    list->tail = entry->prev;

  free(entry);
  list->numEntry--;
}

void OLSR_DeleteList(OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *del = NULL, *tmp = NULL;
  olsr_bool deleted = OLSR_FALSE;

  if(list->head != NULL){
    tmp = list->head->next;

    while(tmp){
      del = tmp;
      tmp = tmp->next;

      OLSR_DeleteListEntry(list, del);
      deleted = OLSR_TRUE;
    }

    if(list->head != NULL){
      del = list->head;
      OLSR_DeleteListEntry(list, del);

      deleted = OLSR_TRUE;
    }
  }

  if(list != NULL)
    free(list);
}

void OLSR_DeleteList_Static(OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *del = NULL, *tmp = NULL;
  olsr_bool deleted = OLSR_FALSE;

  if(list->head != NULL){
    tmp = list->head->next;

    while(tmp){
      del = tmp;
      tmp = tmp->next;

      OLSR_DeleteListEntry(list, del);
      deleted = OLSR_TRUE;
    }

    if(list->head != NULL){
      del = list->head;
      OLSR_DeleteListEntry(list, del);

      deleted = OLSR_TRUE;
    }
  }
}

void OLSR_DeleteList_Search(OLSR_LIST *list)
{
  OLSR_LIST_ENTRY *del = NULL, *tmp = NULL;
  olsr_bool deleted = OLSR_FALSE;

  if(list->head != NULL){
    tmp = list->head->next;

    while(tmp){
      del = tmp;
      tmp = tmp->next;

      OLSR_DeleteListEntry_AvoidData(list, del);
      deleted = OLSR_TRUE;
    }

    if(list->head != NULL){
      del = list->head;
      if(list->numEntry != 1){
    abort();
      }
      OLSR_DeleteListEntry_AvoidData(list, del);
      deleted = OLSR_TRUE;
    }
  }

  if(list != NULL)
    free(list);
}
//WIN FIX: Changed the variable name
olsr_bool OLSR_DeleteListHandler(void* olsr,
                 OLSR_LIST *list, void *todelete,
                 OLSR_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY *del = NULL, *tmp = NULL;
  olsr_bool deleted = OLSR_FALSE;

  if(list->head != NULL){
    tmp = list->head->next;

    while(tmp != NULL){
     //WIN FIX: Changed the variable name
      if(handler(olsr, tmp->data, todelete)){
    del = tmp;
    tmp = tmp->next;

    OLSR_DeleteListEntry(list, del);
    deleted = OLSR_TRUE;
      }else{
    tmp = tmp->next;
      }
    }

    if(list->head != NULL){
      //WIN FIX: Changed the variable name
      if(handler(olsr, list->head->data, todelete)){
    del = list->head;
    OLSR_DeleteListEntry(list, del);

    deleted = OLSR_TRUE;
      }
    }
  }
  return deleted;
}
}
