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

#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_olsr_debug.h"
#include "mp_parse_tlv.h"
#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

/*static function prototype*/

static void calc_user_bit(struct tlv_info *);
static void calc_semantics(struct tlv_info *);
static char *get_tlv_value(char *, struct tlv_tuple *);
static char *get_address_tlv_value(char *, struct tlv_tuple_local *);
static char *get_multi_value_address_tlv(char *, struct tlv_tuple_local *);

static void print_tlv_infomations(struct olsrv2 *, struct tlv_info *);
static void print_message_tlv_tuple(struct olsrv2 *, struct tlv_tuple *);
static void print_address_tlv_tuple(struct olsrv2 *, struct tlv_tuple_local *);
static void print_address_tlv(struct olsrv2 *, struct tlv_tuple_local *);


static char *olsr_get_msg_tlv_type(olsr_u8_t);
static void print_message_tlv(struct olsrv2 *);

/*function definitions*/
inline
static char *
get_u8(char *ptr, olsr_u8_t *v)
{
  *v = *ptr++;
  return ptr;
}

inline
static char *
get_u16(char *ptr, olsr_u16_t *v)
{
  //*v = ntohs(*(olsr_u16_t *)ptr);
  memcpy(v, ptr, sizeof(olsr_u16_t));
  *v = ntohs(*v);
  return ptr + sizeof(olsr_u16_t);
}

inline
static char *
get_u32(char *ptr, olsr_u32_t *v)
{
  //*v = ntohl(*(olsr_u32_t *)ptr);
  memcpy(v, ptr, sizeof(olsr_u32_t));
  *v = ntohl(*v);
  return ptr + sizeof(olsr_u32_t);
}

/* calc type and user_bit */
void
calc_user_bit(struct tlv_info *info)
{
  info->user_bit = (info->type & USER_BIT) != 0 ? 1 : 0;
  info->tlv_prot = (info->type & TLV_PROT) != 0 ? 1 : 0;
  info->type = info->type & 0x3f;
}

/* calc various flag */
void
calc_semantics(struct tlv_info *info)
{
  info->no_value_bit = (info->semantics & NO_VALUE) != 0 ? 1 : 0;
  info->extended_bit = (info->semantics & EXTENDED) != 0 ? 1 : 0;
  info->no_index_bit = (info->semantics & NO_INDEX) != 0 ? 1 : 0;
  info->single_index_bit = (info->semantics & SINGLE_INDEX) != 0 ? 1 :0;
  info->multi_value_bit = (info->semantics & MULTI_VALUE) != 0 ? 1 : 0;
}

/* print tlv info */

static
void
print_tlv_infomations(struct olsrv2 *olsr, struct tlv_info *info)
{
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;
  if (olsr_cnf->debug_level < 5)
    return;
  olsr_printf("\t-----------TLV INFOMATIONS-----------------\n");
  olsr_printf("\tType[%u]\n", info->type);
  olsr_printf("\tUserBit[%u]\n", info->user_bit);
  olsr_printf("\tTLV PROT[%u]\n", info->tlv_prot);
  olsr_printf("\tNoValueBit[%u]\n", info->no_value_bit);
  olsr_printf("\tExtendedBit[%u]\n", info->extended_bit);
  olsr_printf("\tNoIndexBit[%u]\n", info->no_index_bit);
  olsr_printf("\tSingleIndexBIt[%u]\n", info->single_index_bit);
  olsr_printf("\tMultiValueBit[%u]\n", info->multi_value_bit);

  return;
}


/*
 * Only about less or equal than 32 bit::OK!!
 */
static char *
get_tlv_value(char *msg_ptr, struct tlv_tuple *tuple)
{
  tuple->value = 0;
  switch (tuple->length)
    {
    case sizeof(olsr_u8_t):
      {
    olsr_u8_t v;
    msg_ptr = get_u8(msg_ptr, &v);
    tuple->value = v;
      }
      break;
    case sizeof(olsr_u16_t):
      {
    olsr_u16_t v;
    msg_ptr = get_u16(msg_ptr, &v);
    tuple->value = v;
      }
      break;
    case sizeof(olsr_u32_t):
      {
    olsr_u32_t v;
    msg_ptr = get_u32(msg_ptr, &v);
    tuple->value = v;
      }
      break;

    default:
      tuple->extended_value = (olsr_u8_t *)olsr_malloc(tuple->length,
                               __FUNCTION__);
      memcpy(tuple->extended_value, msg_ptr, tuple->length);
      msg_ptr += tuple->length;
    }

  return msg_ptr;
}

inline
static char *
get_address_tlv_value(char *msg_ptr, struct tlv_tuple_local *tuple)
{
  tuple->value = 0;
  tuple->multi_value = NULL;
  tuple->extended_value = NULL;

  switch (tuple->length)
    {
    case sizeof(olsr_u8_t):
      {
    olsr_u8_t v;
    msg_ptr = get_u8(msg_ptr, &v);
    tuple->value = v;
      }
      break;
    case sizeof(olsr_u16_t):
      {
    olsr_u16_t v;
    msg_ptr = get_u16(msg_ptr, &v);
    tuple->value = v;
      }
      break;
    case sizeof(olsr_u32_t):
      {
    olsr_u32_t v;
    msg_ptr = get_u32(msg_ptr, &v);
    tuple->value = v;
      }
      break;

    default:
      tuple->extended_value = (olsr_u8_t *)olsr_malloc(tuple->length,
                          __FUNCTION__);
      memcpy(tuple->extended_value, msg_ptr, tuple->length);
      msg_ptr += tuple->length;
    }
  return msg_ptr;
}

inline
static char *
get_multi_value_address_tlv(char *msg_ptr, struct tlv_tuple_local *tuple)
{
  int i;

  if(tuple->one_field_size > sizeof(olsr_u32_t)){
      if(DEBUG_OLSRV2)
      {
      olsr_printf("Not Support\n");
      }
    tuple->extended_value = (olsr_u8_t* )olsr_malloc(tuple->length,
                    __FUNCTION__);

    memcpy(tuple->extended_value, msg_ptr, tuple->length);
    msg_ptr += tuple->length;
  }else{
    tuple->multi_value = (olsr_u32_t* )olsr_malloc(sizeof(olsr_u32_t) * tuple->number_value, __FUNCTION__);
    for(i = 0; i < tuple->number_value; i++){
      switch(tuple->one_field_size){
      case sizeof(olsr_u8_t):
    {
      olsr_u8_t v = *(olsr_u8_t *)msg_ptr;
      msg_ptr += tuple->one_field_size;
      tuple->multi_value[i] = v;
      break;
    }
      case sizeof(olsr_u16_t):
    {
      olsr_u16_t v = *(olsr_u16_t *)msg_ptr;
      msg_ptr += tuple->one_field_size;
      tuple->multi_value[i] = ntohs(v);
      break;
    }
      case sizeof(olsr_u32_t):
    {
      olsr_u32_t v = *(olsr_u32_t *)msg_ptr;
      msg_ptr += tuple->one_field_size;
      tuple->multi_value[i] = ntohl(v);
      break;
    }
      }//for

    }//if

  }

  return msg_ptr;
}


static
void
print_message_tlv_tuple(struct olsrv2 *olsr, struct tlv_tuple *tuple)
{
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;

  if (olsr_cnf->debug_level < 9)
      return;

  olsr_printf("\t\t-------Msg TLV -----------\n");
  olsr_printf("\t\tTLV TYPE[%u]\n", tuple->type);
  olsr_printf("\t\tTLV LENGTH[%u]\n", tuple->length);
  olsr_printf("\t\tTLV VALUE[%u]\n", tuple->value);
  if (tuple->length > sizeof(olsr_u32_t))
    {
      olsr_printf("TLV VALUE HAS over 4bytes value\n");
      int i;
      olsr_printf("TLV ExtensionValue[");
      for (i = 0; i < tuple->length; i++)
    olsr_printf("%u ", tuple->extended_value[i]);
      olsr_printf("]\n");
    }
  return;
}

static
void
print_address_tlv_tuple(struct olsrv2 *olsr, struct tlv_tuple_local *tuple)
{
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;
  if (olsr_cnf->debug_level < 9)
    return;
  olsr_printf("\t\t-------Addr TLV -----------\n");
  olsr_printf("\t\tTLV TYPE[%u]\n", tuple->type);
  olsr_printf("\t\tTLV LENGTH[%u]\n", tuple->length);
  olsr_printf("\t\tMulti Value Bit[%u]\n", tuple->multi_value_bit);
  olsr_printf("\t\tNumber of Value[%u]\n", tuple->number_value);
  olsr_printf("\t\tONE FIELD SIZE[%u]\n", tuple->one_field_size);
  olsr_printf("\t\tINDEX_START[%u]\tINDEX_STOP[%u]\n", tuple->index_start,
      tuple->index_stop);
  olsr_printf("\t\tTLV VALUE[%u]\n", tuple->value);
  if(tuple->multi_value_bit == 0)
  {
    if (tuple->length > sizeof(olsr_u32_t))
    {
      olsr_printf("\t\tTLV VALUE HAS over 4bytes value\n");
      int i;
      olsr_printf("\t\tTLV ExtensionValue[");
      for (i = 0; i < tuple->length; i++)
    olsr_printf("%u ", tuple->extended_value[i]);
      olsr_printf("]\n");
    }
  }
  else{
    int i;
    for(i = 0; i < tuple->number_value; i++)
      olsr_printf("\t\tVal[%d] = %u\n", i, tuple->multi_value[i]);
  }

  return;
}

static
void
print_address_tlv(struct olsrv2 *olsr, struct tlv_tuple_local *list)
{
  struct olsrd_config *olsr_cnf = olsr->olsr_cnf;
  if (olsr_cnf->debug_level < 5)
    return;

  struct tlv_tuple_local *tuple = list;
  olsr_printf("------------------------------- == ALL ADDR TLV == --------------------\n");
  while (tuple != NULL)
    {
      olsr_printf("TLV TYPE[%u]\n", tuple->type);
      olsr_printf("TLV LENGTH[%u]\n", tuple->length);
      olsr_printf("MULTI VALUE BIT[%u]\n", tuple->multi_value_bit);
      olsr_printf("NUMBER OF VALUE[%u]\n", tuple->number_value);
      olsr_printf("ONE FIELD SIZE[%u]\n", tuple->one_field_size);
      olsr_printf("INDEX_START[%u]\tINDEX_STOP[%u]\n", tuple->index_start,
          tuple->index_stop);
      olsr_printf("TLV VALUE[%u]\n", tuple->value);
      if(tuple->multi_value_bit == 0)
      {
    if (tuple->length > sizeof(olsr_u32_t))
    {
      olsr_printf("TLV VALUE HAS over 4bytes value\n");
      int i;
      olsr_printf("TLV ExtensionValue[");
      for (i = 0; i < tuple->length; i++)
        olsr_printf("%u ", tuple->extended_value[i]);
      olsr_printf("]\n");
    }
      }
      else
    {
      int i;
      for(i = 0; i < tuple->number_value; i++)
        olsr_printf("Multi Value[%d] = %u\n", i, tuple->multi_value[i]);
    }

      tuple = tuple->next;
    }
  olsr_printf("--------------------------------------------------------------------\n");
  return;
}


static char *olsr_get_msg_tlv_type(olsr_u8_t type)
{
  char *str;

  switch(type){
  case Fragmentation:
    str = "Fragment";
    break;
  case Content_Sequence_Number:
    str = "Content Sequence Number";
    break;
  case Willingness:
    str = "Willingness";
    break;
  case Validity_Time:
    str = "Validity Time";
    break;
  case Interval_Time:
    str = "Interval Time";
    break;
  default:
    str = "Unknown";
    break;
  }
  return str;
}

static
void
print_message_tlv(struct olsrv2 *olsr)
{
  struct olsrd_config *olsr_cnf = olsr->olsr_cnf;
  if (olsr_cnf->debug_level < 2)
    return;

  struct tlv_tuple *tuple = olsr->message_tlv_entry;
  olsr_printf("---------------------- = MSG TLV LIST =  -----------------\n");
  while (tuple != NULL)
    {

      olsr_printf("\tTLV TYPE : %s ", olsr_get_msg_tlv_type(tuple->type));
      olsr_printf("\tLENGTH : %u ", tuple->length);
      olsr_printf("\tVALUE: %u\n", tuple->value);
      if (tuple->length > sizeof(olsr_u32_t))
    {
      olsr_printf("TLV VALUE HAS over 4bytes value\n");
      int i;
      olsr_printf("TLV ExtensionValue[");
      for (i = 0; i < tuple->length; i++)
        olsr_printf("%u ", tuple->extended_value[i]);
      olsr_printf("]\n");
    }
      tuple = tuple->next;
    }
  olsr_printf("----------------------------------------------------------\n\n");
  return;
}

char *parse_packet_tlv(struct olsrv2 *olsr, char *msg_ptr)
{
  /*
     this implementation doesn't process packet tlv
     only through the buffer and padding
  */
  olsr_u16_t tlv_length;

  tlv_length = ntohs(*(olsr_u16_t *)msg_ptr);
  msg_ptr += sizeof(olsr_u16_t);

  //skip msg from msg_ptr to msg_ptr + tlv_length
  msg_ptr += tlv_length;

  return msg_ptr;
}


/*
** parser : message tlv
*/
char *
parse_message_tlv(struct olsrv2 *olsr, char *msg_ptr)
{
  struct tlv_info info;
  olsr_u16_t tlv_length;
  char *tlv_end = NULL;
  struct tlv_tuple *new_tuple = NULL;

  // get tlv_length
  msg_ptr = get_u16(msg_ptr, &tlv_length);

  // Msg include no TLV
  if (tlv_length == 0)
    {
      if(DEBUG_OLSRV2)
      {
      olsr_printf("Msg include no MSG TLV\n");
      }
      return msg_ptr;
    }

  tlv_end = msg_ptr + tlv_length;
  if(DEBUG_OLSRV2)
  {
      olsr_printf("MessageTLVLength[%u]\tStart[%p]\tEnd[%p]\n",
          tlv_length, msg_ptr, tlv_end);
  }

  while (msg_ptr < tlv_end)
    {
      //create new tlv tuple
      new_tuple = (struct tlv_tuple *)olsr_malloc(sizeof(struct tlv_tuple),
                          __FUNCTION__);

      memset(new_tuple, 0, sizeof(struct tlv_tuple));
      new_tuple->next = NULL;
      new_tuple->value = OLSR_FALSE;
      new_tuple->extended_value = NULL;

      //get type field value
      msg_ptr = get_u8(msg_ptr, &info.type);
      // calc userbit & type
      calc_user_bit(&info);

      // get semantics field value
      msg_ptr = get_u8(msg_ptr, &info.semantics);
      calc_semantics(&info);

      debug_code(print_tlv_infomations(olsr, &info));

      //check semantic consistency(packetbb 5.3.1) //update 0913
      if (info.no_value_bit == 1 && info.extended_bit == 1){
      if(DEBUG_OLSRV2)
      {
          olsr_printf("This TLV is not correct1.\n");
      }
      free(new_tuple);
      return tlv_end;
      }

      if(info.no_index_bit == 1 && info.single_index_bit == 1){
      if(DEBUG_OLSRV2)
      {
          olsr_printf("This TLV is not correct2.\n");
      }
      free(new_tuple);
      return tlv_end;
      }

      /*
    if single index bit == 1 , or no_value bit == 1, then
    multi value bit set to zero
      */
      if( (info.single_index_bit == 1 || info.no_value_bit == 1) && info.multi_value_bit == 1 )
    {
        if(DEBUG_OLSRV2)
        {
        olsr_printf("This TLV is not corrent3.\n");
        }
        free(new_tuple);
        return tlv_end;
    }

      //fill the struct
      new_tuple->type = info.type;
      if(info.no_value_bit == 1){
    new_tuple->length = 0;
    new_tuple->value = OLSR_TRUE;
    new_tuple->extended_value = NULL;
      }else{ //no value bit == 0
    if(info.extended_bit == 0){
      olsr_u8_t tmp;
      msg_ptr = get_u8(msg_ptr, &tmp);
      new_tuple->length = tmp;
    }else{
      olsr_u16_t tmp;
      msg_ptr = get_u16(msg_ptr, &tmp);
      new_tuple->length = tmp;
    }

    //check invalid info
    if(check_length_over_limit(msg_ptr, tlv_end, new_tuple->length) == OLSR_FALSE){
      olsr_printf("\n\tWarning : Invalid Message [ length is too long (%u) ] %s(%u)\n", new_tuple->length, __FUNCTION__, __LINE__);
      free(new_tuple);
      return tlv_end;
    }

    msg_ptr = get_tlv_value(msg_ptr, new_tuple);
      }
      debug_code(print_message_tlv_tuple(olsr, new_tuple));

      //Queue the Message TLV
      if (olsr->message_tlv_entry == NULL)
    olsr->message_tlv_entry = new_tuple;
      else
    {
      new_tuple->next = olsr->message_tlv_entry;
      olsr->message_tlv_entry = new_tuple;
    }
    }//while

  if (msg_ptr != tlv_end)
    return tlv_end;

  print_message_tlv(olsr);

  return msg_ptr;
}

/**
 *
 */
char *
parse_address_tlv(struct olsrv2 *olsr, struct tlv_tuple_local **tlv_list, char *msg_ptr, const char num_addr)
{
  struct tlv_info info;
  olsr_u16_t tlv_length;
  char *tlv_end = NULL;
  struct tlv_tuple_local *new_list = NULL;

  // get tlv_length
  msg_ptr = get_u16(msg_ptr, &tlv_length);

  if (tlv_length == 0)
    {
    if(DEBUG_OLSRV2)
    {
        olsr_printf("MSG includes no TLV\n");
    }
    return msg_ptr;
    }

  tlv_end = msg_ptr + tlv_length;

  if(DEBUG_OLSRV2)
  {
      olsr_printf("TLV LENGTH[%u]\tStart[%p]\t\tEnd[%p]\n",
             tlv_length, msg_ptr, tlv_end);
  }


  while (msg_ptr < tlv_end)
    {
      new_list = (struct tlv_tuple_local *)olsr_malloc(sizeof(struct tlv_tuple_local), __FUNCTION__);
      memset(new_list, 0, sizeof(struct tlv_tuple_local));
      new_list->next = NULL;
      new_list->value = OLSR_FALSE;
      new_list->multi_value = NULL;
      new_list->extended_value = NULL;

      // <type>
      msg_ptr = get_u8(msg_ptr, &info.type);
      // calc userbit &type
      calc_user_bit(&info);

      // <semantics>
      msg_ptr = get_u8(msg_ptr, &info.semantics);
      calc_semantics(&info);

      //set semantics
      new_list->semantics = info.semantics;

      debug_code(print_tlv_infomations(olsr, &info));

      //check semantics consitency(packetbb 5.3.1) //update 0913
      if (info.no_value_bit == 1 && info.extended_bit == 1)
    {
        if(DEBUG_OLSRV2)
        {
        olsr_printf("This TLV is not correct1\n");
        }
        free(new_list);
        return tlv_end;
    }

      if (info.no_index_bit == 1 && info.single_index_bit == 1)
    {
        if(DEBUG_OLSRV2)
        {
        olsr_printf("This TLV is not correct2\n");
        }
        free(new_list);
        return tlv_end;
    }

      //fill the struct
      //type
      new_list->type = info.type;

       //index start & stop
      if(info.single_index_bit == 1) // single index bit set to 1
    {
      msg_ptr = get_u8(msg_ptr, &new_list->index_start);
      new_list->index_stop = new_list->index_start;
    }else{ //single index bit set to 0
      //in case of no index bit set or unset
      if(info.no_index_bit == 0){
        msg_ptr = get_u8(msg_ptr, &new_list->index_start);
        msg_ptr = get_u8(msg_ptr, &new_list->index_stop);
      }else{
        new_list->index_start = 0;
        new_list->index_stop = num_addr -1;
      }
    }

      //length
      if(info.no_value_bit == 1){ // no value bit set to 1
    new_list->length = 0;
    new_list->value = OLSR_TRUE;
    new_list->multi_value = NULL;
    new_list->extended_value = NULL;
      }else{ // no value bit set to 0
    // in case of extended bit set or unset
    if(info.extended_bit == 0){
      olsr_u8_t tmp;
      msg_ptr = get_u8(msg_ptr, &tmp);
      new_list->length = tmp;
    }else{
      olsr_u16_t tmp;
      msg_ptr = get_u16(msg_ptr, &tmp);
      new_list->length = tmp;
    }
      }


      //check incosistency
      if(new_list->index_start > new_list->index_stop){
      if(DEBUG_OLSRV2)
      {
          olsr_printf("index_start > index_stop\n");
      }
      free(new_list);
      return tlv_end;
      }

      new_list->number_value =
    new_list->index_stop - new_list->index_start + 1;
      //get value
      if(info.no_value_bit == 0){
    // in case of multi value bit set or unset
    if(info.multi_value_bit == 0){
      new_list->one_field_size = new_list->length;

      //check invalid info
      if(check_length_over_limit(msg_ptr, tlv_end, new_list->length) == OLSR_FALSE){
        olsr_printf("\n\tWarning : Invalid Message [ length is too long(%u)] %s(%u)\n", new_list->length, __FUNCTION__, __LINE__);
        free(new_list);
        return tlv_end;
      }

      msg_ptr = get_address_tlv_value(msg_ptr, new_list);
      new_list->multi_value_bit = 0;
    }else{
      new_list->multi_value_bit = 1;
      new_list->one_field_size = new_list->length / new_list->number_value;

      //check invalid info
      if(check_length_over_limit(msg_ptr, tlv_end, new_list->length) == OLSR_FALSE){
        olsr_printf("\n\tWarning : Invalid Message [ length is too long(%u)] %s(%u)\n", new_list->length, __FUNCTION__, __LINE__);
        free(new_list);
        return tlv_end;
      }

      msg_ptr = get_multi_value_address_tlv(msg_ptr, new_list);
    }
      }

      debug_code(print_address_tlv_tuple(olsr, new_list));

      // QUEUE the Message TLV
      if (*tlv_list == NULL)
    *tlv_list = new_list;
      else
    {
      new_list->next = *tlv_list;
      *tlv_list = new_list;
    }
    }//while

  debug_code(print_address_tlv(olsr, *tlv_list));

  if (msg_ptr != tlv_end)
    return tlv_end;

  return msg_ptr;
}

void
free_message_tlv(struct olsrv2 *olsr)
{

  struct tlv_tuple *tuple = olsr->message_tlv_entry;
  struct tlv_tuple *del = NULL;

  while (tuple)
    {
      if (tuple->extended_value != NULL)
    free(tuple->extended_value);
      del = tuple;
      tuple = tuple->next;
      free(del);
    }

  olsr->message_tlv_entry = NULL;


  return;
}

void
free_address_tlv(struct tlv_tuple_local *tuple)
{
  struct tlv_tuple_local *tmp = tuple, *del = NULL;
  while (tmp)
    {
      if(tmp->extended_value != NULL)
    free(tmp->extended_value);
      if(tmp->multi_value != NULL)
    free(tmp->multi_value);
      del = tmp;
      tmp = tmp->next;
      free(del);
    }
  return;
}

/**
 *
 */
struct tlv_tuple *
get_msg_tlv(struct olsrv2 *olsr, int tlv_type)
{
  struct tlv_tuple *p = olsr->message_tlv_entry;

  while (p)
    {
      if (p->type == tlv_type)
    return p;
      p = p->next;
    }
  return NULL;
}

}
// vim:sw=2:
