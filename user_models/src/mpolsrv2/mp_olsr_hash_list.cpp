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
#include <assert.h>
#include <string.h>

#include "mp_olsr_list.h"
#include "mp_olsr_util.h"
#include "mp_def.h"
#include "mp_olsr_protocol.h"

#include "mp_olsr.h"
#include "mp_olsr_hash_list.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{

void OLSR_InitHashList(OLSR_HASH_LIST *hash)
{
  int index;

  for(index=0; index<HASHSIZE; index++){
    OLSR_InitList(&hash[index].list);
  }
}

OLSR_LIST_ENTRY *OLSR_LookupHashList(void* olsr,
                     OLSR_HASH_LIST *hash,
                     union olsr_ip_addr *trigger)
{
  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_HASH_LIST_ENTRY *hash_entry = NULL;

  olsr_u32_t hash_index;

  hash_index = olsr_hashing((struct olsrv2*)olsr,trigger);

  tmp = hash[hash_index].list.head;
  while(tmp){
    hash_entry = (OLSR_HASH_LIST_ENTRY *)tmp->data;
    if(equal_ip_addr((struct olsrv2*)olsr, &hash_entry->trigger, trigger) == 0)
      return tmp;

    tmp = tmp->next;
  }

  return NULL;
}

OLSR_HASH_LIST_ENTRY *OLSR_LookupHashListEntry(void* olsr,
                           OLSR_HASH_LIST *hash,
                           union olsr_ip_addr *trigger)
{
  return (OLSR_HASH_LIST_ENTRY *)OLSR_LookupHashList(olsr, hash, trigger)->data;
}

OLSR_HASH_LIST_ENTRY *OLSR_InsertHashList(void* olsr,
                      OLSR_HASH_LIST *hash,
                      union olsr_ip_addr *trigger,
                      void *data,
                      olsr_u32_t size)
{
  OLSR_HASH_LIST_ENTRY hash_entry;
  olsr_u32_t hash_index;

  olsr_ip_copy((struct olsrv2*)olsr, &hash_entry.trigger, trigger);

  hash_entry.data = olsr_malloc(size, __FUNCTION__);
  memcpy(hash_entry.data, data, size);

//Fix: Initialization missing
  hash_entry.size = size;

  hash_index = olsr_hashing((struct olsrv2*)olsr,trigger);

  OLSR_InsertList(&hash[hash_index].list,
          &hash_entry,
          sizeof(OLSR_HASH_LIST_ENTRY));

  return (OLSR_HASH_LIST_ENTRY *)hash[hash_index].list.tail->data;
}

void OLSR_DeleteHashList(void* olsr,
             OLSR_HASH_LIST *hash, union olsr_ip_addr *trigger)
{
  OLSR_LIST_ENTRY *tmp_hash = NULL, *del_hash = NULL;
  olsr_u32_t hash_index;

  hash_index = olsr_hashing((struct olsrv2*)olsr,trigger);

  tmp_hash = hash[hash_index].list.head;
  while(tmp_hash){
    OLSR_HASH_LIST_ENTRY *hash_entry;

    hash_entry = (OLSR_HASH_LIST_ENTRY *)tmp_hash->data;

    del_hash = tmp_hash;
    tmp_hash = tmp_hash->next;

    if(equal_ip_addr((struct olsrv2*)olsr, &hash_entry->trigger, trigger)){
      free(hash_entry->data);
      OLSR_DeleteListEntry(&hash[hash_index].list, del_hash);
    }
  }

  if(hash[hash_index].list.head == NULL)
    OLSR_DeleteList_Static(&hash[hash_index].list);
}


void OLSR_DeleteHashList_Handler(void* olsr,
                 OLSR_HASH_LIST *hash, void *todelete,
                 OLSR_HASH_LIST_HANDLER handler)
{
  OLSR_LIST_ENTRY *tmp_hash = NULL, *del_hash = NULL;
  olsr_u32_t index;

  assert(handler != NULL);

  for(index=0; index<HASHSIZE; index++){
    tmp_hash = hash[index].list.head;
    while(tmp_hash){
      OLSR_HASH_LIST_ENTRY *hash_entry;

      hash_entry = (OLSR_HASH_LIST_ENTRY *)tmp_hash->data;

      del_hash = tmp_hash;
      tmp_hash = tmp_hash->next;

      if(handler(olsr, hash_entry->data, todelete)){
      free(hash_entry->data);
    OLSR_DeleteListEntry(&hash[index].list, del_hash);
      }
    }

    if(hash[index].list.head == NULL)
      OLSR_DeleteList_Static(&hash[index].list);
  }
}
}
