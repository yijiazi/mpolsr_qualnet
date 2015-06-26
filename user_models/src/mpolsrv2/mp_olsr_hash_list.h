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
#ifndef __MPOLSR_HASH_LIST
#define __MPOLSR_HASH_LIST

#include "mp_olsr_list.h"
#include "mp_olsr_types.h"

namespace MPOLSRv2{

#define HASHSIZE    32
#define HASHMASK    (HASHSIZE - 1)


typedef struct olsr_hash_list_entry
{
  union olsr_ip_addr trigger;

  void *data;
  olsr_u32_t size;
}OLSR_HASH_LIST_ENTRY;

typedef struct olsr_hash_list
{
  OLSR_LIST list;
}OLSR_HASH_LIST;

typedef olsr_bool (*OLSR_HASH_LIST_HANDLER)(void*, void *, void *);

void OLSR_InitHashList(OLSR_HASH_LIST *);
OLSR_LIST_ENTRY *OLSR_LookupHashList(void* olsr,
                     OLSR_HASH_LIST *,
                     union olsr_ip_addr *);
OLSR_HASH_LIST_ENTRY *OLSR_LookupHashListEntry(void* olsr,
                           OLSR_HASH_LIST *,
                           union olsr_ip_addr *);

OLSR_HASH_LIST_ENTRY *OLSR_InsertHashList(OLSR_HASH_LIST *,
                      union olsr_ip_addr *,
                      void *,
                      olsr_u32_t);

void OLSR_DeleteHashList(void*, OLSR_HASH_LIST *, union olsr_ip_addr *);
void OLSR_DeleteHashList_Handler(void*, OLSR_HASH_LIST *, void *, OLSR_HASH_LIST_HANDLER);
}

#endif
