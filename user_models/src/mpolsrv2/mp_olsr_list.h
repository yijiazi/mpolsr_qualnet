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
#ifndef __MPOLSR_LIST_H
#define __MPOLSR_LIST_H

#include "mp_olsr_common.h"
namespace MPOLSRv2{


typedef struct olsr_list_entry
{
  void *data;
  olsr_u32_t size;
  struct olsr_list_entry *next;
  struct olsr_list_entry *prev;
}OLSR_LIST_ENTRY;

typedef struct olsr_list
{
  olsr_u32_t numEntry;
  OLSR_LIST_ENTRY *head;
  OLSR_LIST_ENTRY *tail;
}OLSR_LIST;

typedef olsr_bool (*OLSR_LIST_HANDLER)(void*, void *, void *);

/* function prototypes */
OLSR_LIST_ENTRY *OLSR_InsertListEntry(OLSR_LIST *, OLSR_LIST_ENTRY *);
OLSR_LIST_ENTRY *OLSR_InsertList(OLSR_LIST *, void *, olsr_u32_t);
OLSR_LIST_ENTRY *OLSR_InsertList_Sort(void* olsr,
                      OLSR_LIST *list,
                      void *data, olsr_u32_t size,
                      OLSR_LIST_HANDLER handler);
OLSR_LIST *OLSR_SearchList(void*, OLSR_LIST *, void *, OLSR_LIST_HANDLER);
olsr_bool OLSR_CheckMatchExist(void*,  OLSR_LIST *, void *, OLSR_LIST_HANDLER);
int OLSR_CheckMatchEntryNum(void*, OLSR_LIST *, void *, OLSR_LIST_HANDLER);
#if defined __cplusplus
//extern "C" {
#endif
void OLSR_InitList(OLSR_LIST *);
void OLSR_CopyList(OLSR_LIST *, OLSR_LIST *);
void OLSR_DeleteListEntry(OLSR_LIST *, OLSR_LIST_ENTRY *);
void OLSR_DeleteList_Static(OLSR_LIST *);
void OLSR_DeleteList_Search(OLSR_LIST *);
void OLSR_List_sort(void*,
            OLSR_LIST* list, OLSR_LIST_HANDLER handler);
#if defined __cplusplus
//}
#endif

void OLSR_DeleteList(OLSR_LIST *);
olsr_bool OLSR_DeleteListHandler(void*, OLSR_LIST *, void *, OLSR_LIST_HANDLER);

}
#endif
