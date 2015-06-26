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
#include "mp_olsr_debug.h"
#include "mp_parse_address.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2 {
//extern size_t ipsize;

static char *get_address_block_header(struct olsrv2* olsr,
                      struct address_block_info *,
                      char *msg_ptr);
static void make_address(union olsr_ip_addr *, union olsr_ip_addr *,
             struct address_block_info *);


static
void
print_address_block_info(struct olsrv2 *, struct address_block_info *);
static void print_new_list(struct olsrv2 *, struct address_list *);
static void print_address_list(struct olsrv2 *,struct address_list *);


/*
  function definitions
*/
inline
static char *
get_u8(char *ptr, olsr_u8_t *v)
{
  *v = *ptr++;
  return ptr;
}

void
init_parse_address(struct olsrv2 *olsr)
{

  olsr->message_tlv_entry = NULL;
}

/*
 *
 */
static char *
get_address_block_header(struct olsrv2* olsr,
             struct address_block_info *info, char *msg_ptr)
{

  olsr_u8_t head_octet, tail_octet;

  msg_ptr = get_u8(msg_ptr, &info->num_addr);

  // check head_length & no_tail bit
  msg_ptr = get_u8(msg_ptr, &head_octet);
  info->head_length = head_octet & GET_HEAD_LENGTH;
  info->no_tail = (head_octet & NO_TAIL) != 0 ? 1 : 0;

  // get head
  memset(&info->head, 0 , sizeof(union olsr_ip_addr));
  msg_ptr = get_bytes(msg_ptr, info->head_length, &info->head);

  //check invalid info
  if(info->head_length > olsr->olsr_cnf->ipsize)
    olsr_printf("\n\tWarning : [length is too long (%u) ] %s(%u)\n", info->head_length, __FUNCTION__, __LINE__);

  //check tail part
  if(info->no_tail == 0){ // contains tail
    msg_ptr = get_u8(msg_ptr, &tail_octet);
    info->tail_length = tail_octet & GET_TAIL_LENGTH;
    info->zero_tail = (tail_octet & ZERO_TAIL) != 0 ? 1 : 0;

    //get tail
    memset(&info->tail, 0, sizeof(union olsr_ip_addr));
    if(info->zero_tail == 0)
      msg_ptr = get_bytes(msg_ptr, info->tail_length, &info->tail);

    //check invalid info
    if(info->tail_length > olsr->olsr_cnf->ipsize)
      olsr_printf("\n\tWarning : [length is too long (%u) ] %s(%u)\n", info->head_length, __FUNCTION__, __LINE__);

  }else{ // not includes tail
    info->tail_length = 0;
    info->zero_tail = 1;
  }

  //mid_length
  info->mid_length = (olsr_u8_t)olsr->olsr_cnf->ipsize - info->head_length - info->tail_length;

  return msg_ptr;
}


static
void
print_address_block_info(struct olsrv2 *olsr, struct address_block_info *info)
{
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;
  if (olsr_cnf->debug_level < 9)
    return;
  olsr_printf("\t-------- ADDR BLOCK INFO ---------\n");
  olsr_printf("\tNUMBER OF ADDRESS[%u]\n", info->num_addr);
  olsr_printf("\tHEAD_LEN[%u]\n", info->head_length);
  if(info->head_length != 0)
  {
      char* paddr = olsr_niigata_ip_to_string(olsr, &info->head);
      olsr_printf("IP ADDRESS[%s]\n", paddr);
      free(paddr);
  }
  else
    olsr_printf("\tHEAD_ADDR[%s]\n", "0.0.0.0(none)");
  olsr_printf("\tNoTailFlag = %u\n", info->no_tail);
  olsr_printf("\tZeroTailFlag = %u\n", info->zero_tail);
  olsr_printf("\tTAIL_LEN[%u]\n", info->tail_length);
  if(info->tail_length != 0)
  {
      char* paddr = olsr_niigata_ip_to_string(olsr, &info->tail);
      olsr_printf("IP ADDRESS[%s]\n", paddr);
      free(paddr);
  }
  else
    olsr_printf("\tTAIL_ADDR[%s]\n", "0.0.0.0(none)");

  olsr_printf("\tMidLength[%u]\n", info->mid_length);
  olsr_printf("\t====================================\n");

  return;
}

static void
print_new_list(struct olsrv2 *olsr, struct address_list *entry)
{
  struct olsrd_config *olsr_cnf = olsr->olsr_cnf;

  if (olsr_cnf->debug_level < 5)
    return;
  olsr_printf("\t\t ---------- ONE ADDR INFO ------\n");
  char* paddr = olsr_niigata_ip_to_string(olsr, &entry->ip_addr);
  olsr_printf("IP_ADDRESS[%s]\n", paddr);
  free(paddr);
  olsr_printf("\t\tINDEX[%u]\n", entry->index);

  return;
}

static void
print_address_list(struct olsrv2 *olsr, struct address_list *list)
{
  struct olsrd_config *olsr_cnf = olsr->olsr_cnf;
  struct address_list *tmp;

  if (olsr_cnf->debug_level < 5)
    return;

  tmp = list;
  olsr_printf("\t ------------- ALL ADDR INFO -------------\n");
  while (tmp)
    {
    char* paddr = olsr_niigata_ip_to_string(olsr, &tmp->ip_addr);
    olsr_printf("IP ADDRESS[%s]\n", paddr);
    free(paddr);
    olsr_printf("\tINDEX[%u]\n", tmp->index);
    tmp = tmp->next;
    }
  olsr_printf("\t __________________________________________\n");
  return;
}


/**
 *
 */
inline static void make_address(union olsr_ip_addr *addr,
                union olsr_ip_addr *mid,
                struct address_block_info *info)
{
  char*  dst = (char* )addr;

  memcpy(dst, &info->head, info->head_length);
  dst += info->head_length;
  memcpy(dst, mid, info->mid_length);
  dst += info->mid_length;
  memcpy(dst, &info->tail, info->tail_length);
}

/*
 *
 */
char *
parse_address(struct olsrv2 *olsr, struct address_list **list, char *msg_ptr, char *num_addr)
{
  struct address_block_info info;
  struct address_list *new_list = NULL, *tail = NULL;
  int i;
  union olsr_ip_addr mid;

  msg_ptr = get_address_block_header(olsr, &info, msg_ptr);

  debug_code(print_address_block_info(olsr, &info));
  *num_addr = info.num_addr;// use after
  tail = NULL;

  for (i = 0; i < info.num_addr; i++)
    {
      new_list = (struct address_list *)olsr_malloc(sizeof(struct address_list), __FUNCTION__);
      memset(new_list, 0, sizeof(struct address_list));
      memset(&mid, 0, sizeof(union olsr_ip_addr));
      new_list->next = NULL;

      new_list->index = i;
      msg_ptr = get_bytes(msg_ptr, info.mid_length, &mid);
      make_address(&new_list->ip_addr, &mid, &info);

      debug_code(print_new_list(olsr, new_list));

      // QUEUE address
      if (*list == NULL){
    *list = new_list;
    //tail = new_list;
      }else{
    new_list->next = *list;
    *list = new_list;
    //tail->next = new_list;
    //tail = new_list;
      }
    }

  debug_code(print_address_list(olsr, *list));
  return msg_ptr;
}

void
free_address_list(struct address_list *list)
{
  struct address_list *del, *tmp;
  tmp = list;
  while (tmp)
    {
      del = tmp;
      tmp = tmp->next;
      free(del);
    }
  return;
}




void
create_address_entry(struct olsrv2 *olsr,
    struct address_list *addr_list, struct tlv_tuple_local *tlv_list,
    struct address_tuple** address_entry)
{
  struct address_tuple *new_tuple = NULL;
  struct tlv_tuple *new_tlv = NULL;
  struct address_list *tmp_addr = addr_list;
  struct tlv_tuple_local *tmp_tlv = NULL;
  int addr_index;


  while (tmp_addr)
    {
      new_tuple = (struct address_tuple*)olsr_malloc(sizeof(struct address_tuple),
                             __FUNCTION__);
      memset(new_tuple, 0, sizeof(struct address_tuple));
      olsr_ip_copy(olsr, &new_tuple->ip_addr, &tmp_addr->ip_addr);
      new_tuple->ip_version = olsr->olsr_cnf->ip_version;
      new_tuple->next = NULL;
      new_tuple->addr_tlv = NULL;

      tmp_tlv = tlv_list;
      addr_index = tmp_addr->index;
      while (tmp_tlv)
    {

      if(addr_index < tmp_tlv->index_start || tmp_tlv->index_stop < addr_index)
        {
          tmp_tlv = tmp_tlv->next;
          continue;
        }

      new_tlv = (struct tlv_tuple *)olsr_malloc(sizeof(struct tlv_tuple),
                            __FUNCTION__);
      memset(new_tlv, 0, sizeof(struct tlv_tuple));
      new_tlv->type = tmp_tlv->type;
      new_tlv->length = tmp_tlv->one_field_size;
      new_tlv->next = NULL;

      // set value(in case multi value bit unset)
      if(tmp_tlv->multi_value_bit == 0)
        {
          // in case ,value is less or equal than 32 bit
          if (tmp_tlv->one_field_size <= sizeof(olsr_u32_t))
        {
          new_tlv->value = tmp_tlv->value;
          new_tlv->extended_value = NULL;
        }
          // in case ,value is larger or than 32 bit
          else
        {
          new_tlv->value = 0;
          new_tlv->extended_value = (olsr_u8_t *)olsr_malloc(tmp_tlv->length,
                                __FUNCTION__);
          memcpy(new_tlv->extended_value, tmp_tlv->extended_value,
             sizeof(tmp_tlv->length));
        }
        }
      // in case, multi value bit set
      else
        {// less equal 32 bit // maybe ,too last speed
          if (tmp_tlv->one_field_size <= sizeof(olsr_u32_t))
        {
          new_tlv->value = tmp_tlv->multi_value[addr_index-tmp_tlv->index_start];
          new_tlv->extended_value = NULL;
        }
          // greater than 32 bit
          else
        {
          new_tlv->value = 0;
          new_tlv->extended_value = (olsr_u8_t *)olsr_malloc(tmp_tlv->length,
                               __FUNCTION__);
          memcpy(new_tlv->extended_value, tmp_tlv->extended_value, tmp_tlv->length);
          if(DEBUG_OLSRV2)
          {
              olsr_printf("Not supported!!\n");
          }
        }
        }

      //QUEUE new_tlv
      if (new_tuple->addr_tlv == NULL)
        new_tuple->addr_tlv = new_tlv;
      else
        {
          new_tlv->next = new_tuple->addr_tlv;
          new_tuple->addr_tlv = new_tlv;
        }

      tmp_tlv = tmp_tlv->next;
    }           //while tmp_tlv

      //QUEUE new_tuple
      if (*address_entry == NULL)
    *address_entry = new_tuple;
      else
    {
      new_tuple->next = *address_entry;
      *address_entry = new_tuple;
    }

      tmp_addr = tmp_addr->next;
    }//while tmp_addr

  free_address_list(addr_list);
  free_address_tlv(tlv_list);

  return;
}

// used by free_address_entry

void
free_addr_tlv(struct address_tuple *tmp_tuple)
{
  struct tlv_tuple *tmp = NULL, *del = NULL;

  tmp = tmp_tuple->addr_tlv;
  while (tmp)
    {
      del = tmp;
      tmp = tmp->next;
      free(del->extended_value);
      free(del);
    }
  free(tmp);

  return;
}

static void
free_address_entry(struct address_tuple** entry)
{
  struct address_tuple *tmp_tuple = NULL, *delete_tuple = NULL;
  tmp_tuple = *entry;

  while (tmp_tuple)
    {
      delete_tuple = tmp_tuple;
      free_addr_tlv(delete_tuple);
      tmp_tuple = tmp_tuple->next;

      free(delete_tuple);
    }
  free(tmp_tuple);

  *entry = NULL; //initialize
}


void
free_all_address_entries(struct olsrv2 *olsr)
{
  int i;
  free_address_entry(&olsr->local_interface_block_entry);
  for (i = 0; i < olsr->num_of_addr_tlv_block_entries; ++i)
    free_address_entry(&olsr->addr_tlv_block_entries[i]);
  olsr->num_of_addr_tlv_block_entries = 0;
}

// vim:sw=2:
}
