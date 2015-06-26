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
#include <math.h>

#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
#include <arpa/inet.h>
#endif

#include "mp_olsr_debug.h"
#include "mp_olsr.h"
#include "mp_olsr_util.h"
#include "mp_parse_msg.h"
#include "mp_proc_recv_packet.h"
#include "mp_olsr_common.h"


#include "mp_olsr_util_inline.h"
namespace MPOLSRv2{

#define BYTE 8
#define IPV4_MODE   (olsr_cnf->ip_version == AF_INET)
#define IPV6_MODE   (olsr_cnf->ip_version == AF_INET6)
#define IP_LEN      (IPV4_MODE ? 4 : 16)


/* static function prototype */
static void process_message(struct olsrv2 *olsr,
                union olsr_ip_addr *local_iface,
                union olsr_ip_addr remote_addr);

inline static char *through_padding(char *);



static void print_one_addr_tlv_block(struct olsrv2 *olsr, struct address_tuple*);
static void print_addr_tlv_block(struct olsrv2 *);
static char *olsr_get_addr_tlv_type(olsr_u8_t);

/* function definition */
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
  // *v = ntohs(*(olsr_u16_t *)ptr);
  memcpy(v, ptr, sizeof(olsr_u16_t));
  *v = ntohs(*v);
  return ptr + sizeof(olsr_u16_t);
}

inline
static char *
get_u32(char *ptr, olsr_u32_t *v)
{
  // *v = ntohl(*(olsr_u32_t *)ptr);
  memcpy(v, ptr, sizeof(olsr_u32_t));
  *v = ntohl(*v);
  return ptr + sizeof(olsr_u32_t);
}
inline
static char *
get_ip(struct olsrv2 *olsr, char *ptr, union olsr_ip_addr *addr)
{
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;
  if(olsr_cnf->ip_version == AF_INET){
    memcpy(&addr->v4, ptr, sizeof(olsr_u32_t));
    //addr->v4 = *(olsr_u32_t *)ptr;
    ptr += sizeof(olsr_u32_t);
  }else{
    memcpy(addr, ptr, IP_LEN);
    ptr += IP_LEN;
  }

  return ptr;
}

void
olsr_init_parser(struct olsrv2 *olsr)
{
  int i;

  olsr->parse_functions = NULL;
  olsr_init_package_process(olsr);

  olsr->local_interface_block_entry = NULL;
  for (i = 0; i < MAX_ADDR_TLV_BLOCK_ENTRIES; ++i)
    olsr->addr_tlv_block_entries[i] = NULL;
  olsr->num_of_addr_tlv_block_entries = 0;

}

/**
 *
 */
void
olsr_parser_add_function(struct olsrv2 *olsr, parse_function_type function,
    olsr_u32_t type, int forward_flag)
{
  struct parse_function_entry *new_entry;

  /* allocate parse_function_entry's  memory */
  new_entry =
      (struct parse_function_entry *)
    olsr_malloc(sizeof(struct parse_function_entry), __FUNCTION__);
  new_entry->function = function;
  new_entry->type = type;
  new_entry->is_forward = forward_flag;

  /* queue parse_function entries */
  new_entry->next = olsr->parse_functions;
  olsr->parse_functions = new_entry;

  if(DEBUG_OLSRV2)
  {
      olsr_printf("New parse_function created\tTYPE:%lu\n", type);
  }
}

/**
 *
 */
int
olsr_parser_remove_function(struct olsrv2 *olsr, parse_function_type function,
    olsr_u32_t type, int forward_flag)
{
  struct parse_function_entry *delete_entry, *prev_entry;

  delete_entry = olsr->parse_functions;
  prev_entry = NULL;

  if (delete_entry == NULL)
    {
    if(DEBUG_OLSRV2)
    {
        olsr_printf("parse_functions don't Exist\n");
    }
    return 0;
    }

  while (delete_entry)
    {
      if ((delete_entry->function == function) &&
          (delete_entry->type == type) &&
          (delete_entry->is_forward == forward_flag))
    {
      if (delete_entry == olsr->parse_functions)
        /* At first matched ,delete this parse_functions */
        olsr->parse_functions = delete_entry->next;
      else
        /* delete this parse_functions */
        prev_entry->next = delete_entry->next;
      free(delete_entry);
      return 1;
    }

      /* search next parse_functions */
      prev_entry = delete_entry;
      delete_entry = delete_entry->next;
    }

  if(DEBUG_OLSRV2)
  {
      olsr_printf("Search Exit. Entry doesn't exist\n");
  }

  return 0;         /* parse_function not found */
}



/* static function */

typedef olsr_u32_t olsr_ptr_t;


static olsr_u16_t
skip_padding(olsr_u16_t size)
{
  if (size % 4 != 0)
    size += 4 - size % 4;
  return size;
}


inline
static
char *through_padding(char *msg_ptr)
{
  while(*msg_ptr == 0)
    msg_ptr++;
  return msg_ptr;
}

/*
 * { <addr-block> <tlv-block> }
 */
static char *
parse_addr_tlv_block(struct olsrv2 *olsr, char *msg_ptr,
             struct address_tuple** entry)
{
  struct address_list *addr_list = NULL;
  struct tlv_tuple_local *addr_tlv = NULL;
  char num_addr;

  // parse <addr-block>
  msg_ptr = parse_address(olsr, &addr_list, msg_ptr, &num_addr);
  // local_interface_block entry
  if(olsr->num_of_local_interface_block_entry == 0)
    olsr->num_of_local_interface_block_entry = num_addr;
  // olsr_printf(" Num Of Local Interface Block ENtry = %u\n",
  // olsr->num_of_local_interface_block_entry);
  // parse <tlv-block> (address tlv)
  msg_ptr = parse_address_tlv(olsr, &addr_tlv, msg_ptr, num_addr);
  create_address_entry(olsr, addr_list, addr_tlv, entry);

  return msg_ptr;
}

/*
 *
 */
static char *
parse_message_header(struct olsrv2 *olsr, char *msg_ptr)
{
  struct message_header *const mh = &olsr->message_header;

  // <msg-header>
  msg_ptr = get_u8(msg_ptr, &mh->message_type);
  msg_ptr = get_u8(msg_ptr, &mh->semantics);
  msg_ptr = get_u16(msg_ptr, &mh->message_size);

  // <msg-header-info>
  if((mh->semantics & NO_ORIG_HOP) != 0){
      if(DEBUG_OLSRV2)
      {
      olsr_printf("This packet has unknown semantics\n");
      }
      return NULL;
  }
  msg_ptr = get_ip(olsr, msg_ptr, &mh->orig_addr);
  msg_ptr = get_u8(msg_ptr, &mh->ttl);
  msg_ptr = get_u8(msg_ptr, &mh->hop_count);
  msg_ptr = get_u16(msg_ptr, &mh->message_seq_num);

  return msg_ptr;
}

/*
 *
 */

static char *
parse_message(struct olsrv2 *olsr, char *msg_ptr, olsr_32_t pkt_remainder,
    union olsr_ip_addr *local_iface,
    union olsr_ip_addr remote_addr)
{
  char *initial_msg_ptr = msg_ptr;
  olsr_32_t remainder_len;
  olsr_32_t msg_length;
  int i;
  struct message_header* message_header;
  olsr_u8_t message_type;

  if (pkt_remainder <= 4)
    return msg_ptr;

  // message header
  if((msg_ptr = parse_message_header(olsr, msg_ptr)) == NULL)
    return NULL;

  msg_length = olsr->message_header.message_size;

  olsr->message_body = msg_ptr;     // save for forwarding.
  olsr->message_body_size = msg_length - (msg_ptr - initial_msg_ptr);

  message_header = &olsr->message_header;
  message_type = message_header->message_type;




  // unknown type
  if(message_type != HELLO_MESSAGE && message_type != TC_MESSAGE)
    goto forward;

  // msg tlv
  msg_ptr = parse_message_tlv(olsr, msg_ptr);
  remainder_len = msg_length - (olsr_32_t)(msg_ptr - initial_msg_ptr);

  olsr->num_of_local_interface_block_entry = 0;
  olsr->local_interface_block_entry = NULL;
  for (i = 0; i < MAX_ADDR_TLV_BLOCK_ENTRIES; ++i)
    olsr->addr_tlv_block_entries[i] = NULL;
  olsr->num_of_addr_tlv_block_entries = 0;

  if (remainder_len > 0)
    {
      struct address_tuple* entry;

      // parse local interface block
      entry = NULL;

      msg_ptr = parse_addr_tlv_block(olsr, msg_ptr, &entry);
      remainder_len = msg_length - (olsr_32_t)(msg_ptr - initial_msg_ptr);
      olsr->local_interface_block_entry = entry;

      while (remainder_len > 0)
    {
      entry = NULL;
      msg_ptr = parse_addr_tlv_block(olsr, msg_ptr, &entry);
      remainder_len = msg_length - (olsr_32_t)(msg_ptr - initial_msg_ptr);
      olsr->addr_tlv_block_entries[olsr->num_of_addr_tlv_block_entries++]
          = entry;
    }
    }
  print_addr_tlv_block(olsr);
  return initial_msg_ptr + skip_padding((olsr_u16_t)msg_length);


 forward:
  if (!proc_forward_set(olsr,
            &message_header->orig_addr,
            &remote_addr,
            message_header->message_seq_num))
    {           //5.4.1
    if(DEBUG_OLSRV2)
    {
        olsr_printf("Message already forwarded!!\n");
    }
    return NULL;
    }
  else
    {           //5.4.2 @ forward message process
    if(DEBUG_OLSRV2)
    {
        olsr_printf("Message forwarding process\n");
    }
    //forward process
    //5.4.2.1....
    forward_message(olsr);
    }
  return NULL;
}



/*
 * parse packet
 */
void
parse_packet(struct olsrv2 *olsr, char *pkt_ptr, olsr_u16_t packet_length,
    union olsr_ip_addr *local_iface,
    union olsr_ip_addr remote_addr)
{
  char *initial_pkt_ptr = pkt_ptr;
  struct packet_header *const pkt_header = &olsr->packet_header;

  // packet header
  if (*pkt_ptr == 0)
    {
      pkt_header->zero = *pkt_ptr++;

      pkt_header->packet_semantics = *pkt_ptr++;
      if((pkt_header->packet_semantics & NO_PSEQNUM) == 0){ //check pnoseqnum(5.1)
    pkt_header->packet_seq_num = ntohs(*(olsr_u16_t*)pkt_ptr);
      }else{
      if(DEBUG_OLSRV2)
      {
          olsr_printf("Error:This packet lacks of packet seq num\n");
      }
      return;
      }
      pkt_ptr += 2;

      //check packet tlv block
      if((pkt_header->packet_semantics & PACKET_TLV) != 0) //check ptlv
    pkt_ptr = parse_packet_tlv(olsr, pkt_ptr);

      //skip padding
      if(*pkt_ptr == 0)
    pkt_ptr = through_padding(pkt_ptr);

    }

  // CHECK WHETHER THIS PACKET HAS ALREADY BEEN PROCESSED OR NOT.

  while (packet_length > 0)
    {
      pkt_ptr = parse_message(olsr, pkt_ptr, packet_length,
          local_iface, remote_addr);

      if(!pkt_ptr)
    return;
      packet_length = packet_length - (olsr_u16_t)(pkt_ptr - initial_pkt_ptr);
      process_message(olsr, local_iface, remote_addr);

      initial_pkt_ptr = pkt_ptr;
    }
}

static void
process_message(struct olsrv2 *olsr,
    union olsr_ip_addr *local_iface,
    union olsr_ip_addr remote_addr)
{
  struct message_header* const m_header = &olsr->message_header;
  union olsr_ip_addr* originator = &m_header->orig_addr;
  olsr_u16_t message_sequence = m_header->message_seq_num;
  const olsr_u8_t message_type = m_header->message_type;

  struct parse_function_entry *parse_func_entry = NULL;
  int processed_flag = 0;


  olsr->stat.numMessageRecv++;
  if(DEBUG_OLSRV2)
  {
      olsr_printf("Increment Message Received Count to %d\n", olsr->stat.numMessageRecv);
  }

  // 5.2
  if (m_header->ttl <= 0 || equal_ip_addr(olsr,
                      originator,
                      local_iface
      ))
    {
      if (message_type == TC_MESSAGE){
    free_all_address_entries(olsr);
    free_message_tlv(olsr);
      }
      return;
    }

  //check msg type v1 message forward (backward compatibility
  if (message_type != HELLO_MESSAGE &&
      message_type != TC_MESSAGE &&
      message_type != MA_MESSAGE)
    goto forward;

  //5.2
  if(message_type == TC_MESSAGE)
    {
      if (!proc_rcv_msg_set(olsr, &remote_addr, m_header)){
      if(DEBUG_OLSRV2)
      {
          olsr_printf("Message already received!!\n");
      }
      free_all_address_entries(olsr);
      free_message_tlv(olsr);
      return;
      }
    }

  //5.2.2
  parse_func_entry = olsr->parse_functions;

  for (parse_func_entry = olsr->parse_functions;
       parse_func_entry != NULL;
       parse_func_entry = parse_func_entry->next)
    {               // 5.2.2
      if (!((parse_func_entry->type == PROMISCOUS) ||
        (parse_func_entry->type == message_type)))
    continue;


      /* 5.3 @message processing */

      /* if msg is hello ,skip proc_proc_set */
      if (((message_type == TC_MESSAGE) || (message_type == MA_MESSAGE)) &&
      (proc_proc_set(olsr, m_header) == OLSR_FALSE))
    {           // 5.3.1 @tuple exit
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Message already processed !!\n");
        }
        processed_flag = 1;
        if(message_type == TC_MESSAGE){
        free_all_address_entries(olsr);
        free_message_tlv(olsr);
        }
        break;
    }
      else          // 5.3.2 @tuple not exist
    {
      //5.3.2.2 @message specific processing
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Message Type:%u specific process!!\n",
               message_type);
        }

        parse_func_entry->function(olsr, m_header, local_iface,
                       &remote_addr);
        //5.4 @message forwarding if forward is considered
        if (parse_func_entry->is_forward)
        {
        processed_flag = 1;
        }
    }
    }


  // 5.4 @ Unknown Message type(5.2.2)
 forward:
  if (processed_flag == 0)
    {
    if(DEBUG_OLSRV2)
    {
        olsr_printf("Unknown Message Type Processing (forward)\n");
    }
    if (!proc_forward_set(olsr, originator, &remote_addr, message_sequence))
    {           //5.4.1
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Message already forwarded!!\n");
        }
        return;
    }
    else
    {           //5.4.2 @ forward message process
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Message forwarding process\n");
        }
        //forward process
        //5.4.2.1....
        forward_message(olsr);
    }
    }

  return;
}

static char *olsr_get_addr_tlv_type(olsr_u8_t type)
{
  char *str;
  switch(type){
  case PREFIX_LENGTH:
    str = "Prefix Length";
    break;
  case Link_Status:
    str = "Link Status";
    break;
  case Other_If:
    str = "Other If";
    break;
  case MPR_Selection:
    str = "MPR";
    break;
  case Other_Neigh:
    str = "Other Neigh";
    break;
  case Gate_Way:
    str = "Gateway";
    break;
  default:
    str ="Unknown";
    break;
  }
  return str;
}


static void print_one_addr_tlv_block(struct olsrv2 *olsr, struct address_tuple* entry)
{
  struct address_tuple *tmp_addr = NULL;
  struct tlv_tuple *tmp_tlv = NULL;
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;

  if(olsr_cnf->debug_level < 2)
      return;

  olsr_printf("------- = ADDR & ADDR TLV = ---------\n");
  tmp_addr = entry;
  while(tmp_addr)
    {
      olsr_printf("*****************************************************\n");
      char* paddr = olsr_niigata_ip_to_string(olsr, &tmp_addr->ip_addr);
      olsr_printf("IP_address[%s]\n",paddr);
      free(paddr);
      olsr_printf("IP_Ver[%d]\n",tmp_addr->ip_version);

      //next
      tmp_tlv = tmp_addr->addr_tlv;
      olsr_printf("\t-----------\n");
      while(tmp_tlv)
    {
      olsr_printf("\tTLV TYPE: %s ", olsr_get_addr_tlv_type(tmp_tlv->type));
      olsr_printf("\tLENGTH: %u ",tmp_tlv->length);
      olsr_printf("\tVALUE[%d]\n",tmp_tlv->value);


      //next
      tmp_tlv = tmp_tlv->next;
    }
      olsr_printf("\t-----------\n");
      //next
      tmp_addr = tmp_addr->next;
    }
  olsr_printf("------------------------------------------\n");
  olsr_printf("\n");
  return;
}


static void print_addr_tlv_block(struct olsrv2 *olsr)
{
  int i;
  struct olsrd_config* olsr_cnf = olsr->olsr_cnf;

  if(olsr_cnf->debug_level < 2)
  return;

  olsr_printf("\n********Local Interface Block*************\n");
  print_one_addr_tlv_block(olsr, olsr->local_interface_block_entry);
  for (i = 0; i < olsr->num_of_addr_tlv_block_entries; ++i)
    {
      olsr_printf("\n********Addr TLV Block %d *************\n", i);
      print_one_addr_tlv_block(olsr, olsr->addr_tlv_block_entries[i]);
    }
}
}

