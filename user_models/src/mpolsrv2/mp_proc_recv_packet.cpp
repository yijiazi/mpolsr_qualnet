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
#include "mp_def.h"
#include "mp_proc_recv_packet.h"
#include "mp_olsr_common.h"
#include "mp_mantissa.h"

#include "mp_proc_link_set.h"
#include "mp_proc_2neigh_set.h"
#include "mp_proc_routing_set.h"
#include "mp_proc_relay_set.h"
#include "mp_proc_adv_neigh_set.h"
#include "mp_proc_mpr_set.h"
#include "mp_proc_mpr_selector_set.h"

#include "mp_proc_topology_set.h"
//#include "proc_associ_set.h"

#include "mp_generate_msg.h"

#include "mp_olsr_conf.h"
#include "mp_olsr_protocol.h"
#include "mp_olsr_list.h"
#include "mp_parse_tlv.h"

#include <assert.h>

#include "mp_olsr_util.h"
#include "mp_proc_symmetric_neighbor_set.h"
#include "mp_proc_attach_network_set.h"
#include "mp_proc_assn_history_set.h"
#include "mp_proc_neighbor_address_association_set.h"


#include "mp_olsr_util_inline.h"
/* static */
namespace MPOLSRv2{

static olsr_bool hello_change_structure(struct olsrv2 *,
                    struct hello_message *, struct message_header *);
static olsr_bool tc_change_structure(struct olsrv2 *, struct tc_message *,
                     struct message_header *, union olsr_ip_addr *);
static olsr_bool process_hello(struct olsrv2 *olsr, struct hello_message *,
                   union olsr_ip_addr *,
                   union olsr_ip_addr *);
static olsr_bool process_tc(struct olsrv2 *olsr, struct tc_message *,
                union olsr_ip_addr *
                );

static olsr_u8_t get_validity_time_from_hop(struct tlv_tuple *, olsr_u8_t );


static void print_hello_message(struct olsrv2 *, struct hello_message *);
static void print_tc_message(struct olsrv2 *, struct tc_message *tc);


/**
 * Initializing the parser functions we are using
 */
void
olsr_init_package_process(struct olsrv2 *olsr)
{
  olsr_parser_add_function(olsr, &olsr_process_received_hello, HELLO_MESSAGE, 1);
  olsr_parser_add_function(olsr, &olsr_process_received_tc, TC_MESSAGE, 1);
}


/**
 * Processes a received HELLO message.
 */
void
olsr_process_received_hello(struct olsrv2 *olsr, struct message_header *m,
                union olsr_ip_addr *in_if,
                union olsr_ip_addr *from_addr)
{
  struct hello_message message;

  if (hello_change_structure(olsr, &message, m) == OLSR_FALSE)
  {// wiss: bi 3abi kell el ma3loumet bel "message" w iza fet lahon ma3neta tghayar el form ...bisir bi tayer el message
//Fix for Memory Loss // wiss: sar fi deformation bel message men tayerou
      olsr_free_hello_packet(&message);
      return;
  }

  process_hello(olsr, &message, in_if, from_addr);
  olsr_free_hello_packet(&message);

  olsr->stat.numHelloReceived++;
  if(DEBUG_OLSRV2)
  {
      olsr_printf("Increment Hello Message Received Count to %d\n", olsr->stat.numHelloReceived);
  }
  return;
}

/**
 * Process a received TopologyControl message
 */
void
olsr_process_received_tc(struct olsrv2 *olsr, struct message_header *m,
             union olsr_ip_addr *in_if,
             union olsr_ip_addr *from_addr)
{
  struct tc_message message;

  if (tc_change_structure(olsr, &message, m, from_addr) == OLSR_FALSE){
//Fix for Memory Loss
    olsr_free_tc_packet(&message);
    return;
  }
  process_tc(olsr, &message, in_if);
  olsr_free_tc_packet(&message);

  olsr->stat.numTcReceived++;
  if(DEBUG_OLSRV2)
  {
      olsr_printf("Increment Tc Message Received Count to %d\n", olsr->stat.numTcReceived);
  }
  return;
}

/*
  static functions
*/

static olsr_bool
hello_change_structure(struct olsrv2 *olsr, struct hello_message *h_msg,
               struct message_header *m)
{
  struct address_tuple *tmp_addr_entry = NULL;
  struct tlv_tuple *tlv_entry = NULL;
  struct hello_neighbor *neigh = NULL;
  olsr_u8_t link_status_count;
  olsr_u8_t mpr_selection_count;
  olsr_u8_t other_neigh_count;

  //olsr_bool link_status_flag;
  //olsr_bool mpr_selection_flag;
  //olsr_bool other_neigh_flag;
  olsr_bool add_neigh;

  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY local_iface_entry;

//MEMSET added for Linux
  memset(&local_iface_entry, 0, sizeof(OLSR_LOCAL_INTERFACE_BLOCK_ENTRY));

  int i;


  //initialize
  memset(h_msg, 0, sizeof(struct hello_message));
  //wiss: fill validity from message tlv
  tlv_entry = get_msg_tlv(olsr, Validity_Time);  // byetle3 3enna men el olsr el TLV_entry yalli 3endou tlv_type "Validity_Time"
  if(tlv_entry->length == 1)
    h_msg->vtime = me_to_double((olsr_u8_t)tlv_entry->value);
  else// greater than 3 byte
    h_msg->vtime = get_validity_time_from_hop(tlv_entry, m->hop_count);

  h_msg->htime = (double)h_msg->vtime/3; //wiss: ma fhemet chou hiye el htime

  //olsr_ip_copy(&h_msg->source_addr, &m->orig_addr);
  tmp_addr_entry = olsr->local_interface_block_entry;
  olsr_ip_copy(olsr, &h_msg->source_addr, &tmp_addr_entry->ip_addr);
  olsr_ip_copy(olsr, &h_msg->orig_addr, &m->orig_addr);
  //olsr_printf("Source = %s\n", IP_TO_STRING(&h_msg->source_addr));


  h_msg->hop_count = m->hop_count;
  h_msg->ttl = m->ttl;
  h_msg->message_seq_number = m->message_seq_num;

  // fill willingness from message tlv
  if((tlv_entry = get_msg_tlv(olsr, Willingness)) == NULL){
    // default //wiss: ya3ni hon ma la2a TLV willingness donc will_default
    h_msg->willingness = WILL_DEFAULT;
  }else{
    // assume that willingness is less equal than 4byte
    h_msg->willingness = (olsr_u8_t)tlv_entry->value;
  }

  //codexxx
  tlv_entry = get_msg_tlv(olsr, queuelen);
   h_msg->queuelength = (olsr_u8_t)tlv_entry->value;
  
  //end codexxx

  //local interface block
  OLSR_InitList(&h_msg->local_iface_list);
  tmp_addr_entry = olsr->local_interface_block_entry;
  while(tmp_addr_entry) {
    olsr_ip_copy(olsr, &local_iface_entry.iface_addr, &tmp_addr_entry->ip_addr);
    local_iface_entry.other_if = OLSR_FALSE;

    tlv_entry = tmp_addr_entry->addr_tlv;
    while(tlv_entry) {
      switch(tlv_entry->type){
      case Other_If:
    local_iface_entry.other_if = (olsr_u8_t)tlv_entry->value;
    break;
      default:
    break;
      }
      tlv_entry = tlv_entry->next;
    } // wiss: set local_iface_entry.other_if
    OLSR_InsertList(&h_msg->local_iface_list, &local_iface_entry,
            sizeof(OLSR_LOCAL_INTERFACE_BLOCK_ENTRY));

    tmp_addr_entry= tmp_addr_entry->next;
  }
// wiss : lahon biikoun tmalla el hello message "h_msg" bi kell el ma3loumet el lezme ella el champs "neighbors"
  //test
/*   olsr_ip_copy(&local_iface_entry.iface_addr, &olsr->local_interface_block_entry->ip_addr); */
/*   local_iface_entry.iface_addr.v4 += 1; */
/*   local_iface_entry.other_if = OLSR_FALSE; */
/*   OLSR_InsertList(&h_msg->local_iface_list, &local_iface_entry, */
/*        sizeof(OLSR_LOCAL_INTERFACE_BLOCK_ENTRY)); */

/*   olsr_ip_copy(&local_iface_entry.iface_addr, &olsr->local_interface_block_entry->ip_addr); */
/*   local_iface_entry.iface_addr.v4 += 2; */
/*   local_iface_entry.other_if = OLSR_FALSE; */
/*   OLSR_InsertList(&h_msg->local_iface_list, &local_iface_entry, */
/*        sizeof(OLSR_LOCAL_INTERFACE_BLOCK_ENTRY)); */

  // all neighbor :advertized by hello
  h_msg->neighbors = NULL;
  for (i = 0; i < olsr->num_of_addr_tlv_block_entries; ++i){
    tmp_addr_entry = olsr->addr_tlv_block_entries[i];
    while (tmp_addr_entry)
      {
    neigh = (struct hello_neighbor *)olsr_malloc(sizeof(struct hello_neighbor), __FUNCTION__);
    memset(neigh, 0, sizeof(struct hello_neighbor));

    add_neigh = OLSR_TRUE;


    tlv_entry = tmp_addr_entry->addr_tlv;
    link_status_count = mpr_selection_count = other_neigh_count = 0;
    //link_status_flag = mpr_selection_flag = other_neigh_flag = OLSR_FALSE;


    neigh->is_mpr = OLSR_FALSE;
    neigh->status = 255;
    neigh->other_neigh = 255;

    while (tlv_entry){
      switch (tlv_entry->type)
        {
        case Link_Status:
          link_status_count++;
          //link_status_flag = OLSR_TRUE;
          //assume that link status is less equal than 4byte
          neigh->status = (olsr_u8_t)tlv_entry->value;
          break;
        case MPR_Selection:
          mpr_selection_count++;
          //assume that mpr selection is less equal than 4byte
          neigh->is_mpr = OLSR_TRUE;
          break;
        case Other_Neigh:
          other_neigh_count ++;
          //other_neigh_flag = OLSR_TRUE;
          neigh->other_neigh = OLSR_TRUE;
          break;
        default:
          //default ignore
          break;
        }

      tlv_entry = tlv_entry->next;
    }

    // wiss:  la hon menkoun 3abayna el fields taba3 el neigh ella el IP address
    if (link_status_count > 1 || other_neigh_count > 1 || mpr_selection_count > 1)
    {
        if(DEBUG_OLSRV2)
        {
        char* paddr = olsr_niigata_ip_to_string(olsr, &neigh->address);
        olsr_printf("This Neighbor %s have over 2 same tlv type\n",paddr);
        free(paddr);
        }
      add_neigh = OLSR_FALSE; // wiss: bima ennu 3endou aktar men 2 same TLV men7ot add_neigh= false
    }

    if (olsr->olsr_cnf->ip_version == AF_INET){
      //check inconsistency
      if (neigh->is_mpr == OLSR_TRUE && neigh->status != SYMMETRIC)
        {
        if(DEBUG_OLSRV2)
        {
            olsr_printf("MPR have non symmetric link\n");
        }
        free(neigh);

        tmp_addr_entry = tmp_addr_entry->next;
        continue;
        /*
        free_all_address_entries(olsr);
        free_message_tlv(olsr);
        return OLSR_FALSE;
        */
        }

//    if (neigh->transmitting_iface == Other && neigh->status != SYMMETRIC)
//    {
//        if (DEBUG_OLSRV2){
//        olsr_printf("Other Interface have non symmetric link\n");
//        }
//        free_all_address_entries(olsr);
//        free_message_tlv(olsr);
//        free(neigh);
//        return OLSR_FALSE;
//    }

    }

    //add neighbor to hello_message
    if (add_neigh == OLSR_TRUE){ // wiss: bikoun true iza linkstatus count aw mpr count aw ...count <=1
      //copy neigh
      olsr_ip_copy(olsr, &neigh->address, &tmp_addr_entry->ip_addr);
      //queue
      if (h_msg->neighbors == NULL)
        {
          neigh->next = NULL;
          h_msg->neighbors = neigh;
        }
      else
        {
          neigh->next = h_msg->neighbors;
          h_msg->neighbors = neigh;
        }
    }else{// add_neigh == FALSE
      //skip this neighbor
        if(DEBUG_OLSRV2)
        {
        olsr_printf("Neighbor %s don't add neigh list\n");
        }
        free(neigh);
    }

    //next address advertized by hello
    tmp_addr_entry = tmp_addr_entry->next;
      }
  }//for


  if(DEBUG_OLSRV2)
  {
      print_hello_message(olsr, h_msg);
  }

  // free address tlv & message tlv
  free_all_address_entries(olsr);
  free_message_tlv(olsr);

  return OLSR_TRUE;
}


static void
print_hello_message(struct olsrv2 *olsr, struct hello_message *h)
{
  //struct olsrd_config *olsr_cnf = olsr->olsr_cnf;
  struct hello_neighbor *hello_neigh = NULL;
  olsr_u8_t *link = NULL, *mpr = NULL, *iface = NULL;
  char* paddr = NULL;

  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *local_data;
  const OLSR_LIST_ENTRY *local_entry = h->local_iface_list.head;
  /*
  if(olsr_cnf->debug_level < 3)
    return;
  */
  hello_neigh = h->neighbors;
  olsr_printf("\n*****************************************\n");
  olsr_printf("HELLO MESSAGE\n\n");
  olsr_printf("Vtime                         %f\n", h->vtime);
  //  olsr_printf("Htime                     %f\n",h->htime);
  paddr = olsr_niigata_ip_to_string(olsr, &h->source_addr);
  olsr_printf("SouceAddr                     %s\n",paddr);
  free(paddr);

  olsr_printf("MessageSequenceNum            %u\n", h->message_seq_number);
  olsr_printf("HopCount                      %u\n", h->hop_count);
  olsr_printf("TTL                           %u\n", h->ttl);
  olsr_printf("Willingness                   %u\n", h->willingness);
  olsr_printf("* LOCAL INTERFACE LIST *****************\n");

  while(local_entry) {
    local_data = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)local_entry->data;
    paddr = olsr_niigata_ip_to_string(olsr, &local_data->iface_addr);
    olsr_printf("IP ADDRESS                %s\n",paddr);
    free(paddr);
    local_entry = local_entry->next;
  }
  olsr_printf("******************************************\n\n");
  olsr_printf("Neighbor Infomations\n");
  olsr_printf("-------------------------------------------\n");
  while (hello_neigh){
      paddr = olsr_niigata_ip_to_string(olsr, &hello_neigh->address);
      olsr_printf("IP ADDRESS                %s\n",paddr);
      free(paddr);

    olsr_printf("---------------------------------------\n");
    switch (hello_neigh->status)
      {
      case LOST:
    link = (olsr_u8_t *)"LOST";
    break;
      case SYMMETRIC:
    link = (olsr_u8_t *)"SYMMETRIC";
    break;
      case ASYMMETRIC:
    link = (olsr_u8_t *)"ASYMMETRIC";
    break;
      case UNSPEC:
    link = (olsr_u8_t *)"UNSPEC";
      default:
    link = (olsr_u8_t *)"NOTHING";
    break;
      }
    olsr_printf("LinkStatus                %s\n", link);

    switch (hello_neigh->is_mpr)
      {
      case OLSR_TRUE:
    mpr = (olsr_u8_t *)"YES";
    break;
      default:
    mpr = (olsr_u8_t *)"NO";
    break;
      }
    olsr_printf("MPR_Selection             %s\n", mpr);

    switch (hello_neigh->other_neigh)
      {
      case SYMMETRIC:
    iface = (olsr_u8_t *)"SYMMETRIC";
    break;
      case LOST:
    iface = (olsr_u8_t *)"LOST";
    break;
      default:
    iface = (olsr_u8_t *)"NOTHING";
    break;
      }
    olsr_printf("OTHER_NEIGH                  %s\n", iface);


    olsr_printf("-----------------------------------------\n");
    hello_neigh = hello_neigh->next;
  }
  olsr_printf("\n\n");

  return;
}


static struct tlv_tuple *have_attached_network_tlv(struct tlv_tuple *tlv_entry)
{
  struct tlv_tuple *tmpTlvEntry = tlv_entry;
  while(tmpTlvEntry)
    {
      if(tmpTlvEntry->type == PREFIX_LENGTH)
    return tmpTlvEntry;
      tmpTlvEntry = tmpTlvEntry->next;
    }

  return NULL;
}

/*
 *
 */
static olsr_bool
tc_change_structure(struct olsrv2 *olsr, struct tc_message *tc_msg,
            struct message_header *m, union olsr_ip_addr *source)
{
  struct address_tuple *tmp_addr_entry = NULL;
  struct tlv_tuple *tlv_entry = NULL;

  struct tc_mpr_addr *mpr_entry = NULL;
  int i;
  ATTACHED_NETWORK *attached_net_entry = NULL;

  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY local_iface_entry;

  // initialize
  memset(tc_msg, 0, sizeof(struct tc_message));

  // fill ipv4 header informations
  tlv_entry = get_msg_tlv(olsr, Validity_Time);
  if(tlv_entry->length == 1)
    tc_msg->vtime = me_to_double((olsr_u8_t)tlv_entry->value);
  else// greater than 3 byte
    tc_msg->vtime = get_validity_time_from_hop(tlv_entry, m->hop_count);

  olsr_ip_copy(olsr, &tc_msg->source_addr, source);
  olsr_ip_copy(olsr, &tc_msg->originator, &m->orig_addr);
  tc_msg->message_seq_number = m->message_seq_num;
  tc_msg->hop_count = m->hop_count;
  tc_msg->ttl = m->ttl;

  if ((tlv_entry = get_msg_tlv(olsr, Content_Sequence_Number)) == NULL){
    olsr_error("This Message include no ASSN\n");
  }else{//assume that assn is less equal than 4byte
    tc_msg->assn = (olsr_u16_t)tlv_entry->value;
  }
/*
//codexxx'
  tlv_entry = get_msg_tlv(olsr, queuelen);
   tc_msg->queuelength = (olsr_u8_t)tlv_entry->value;
  
  //end codexxx'  
*/
  if(proc_assn_history_set(olsr, &tc_msg->originator, tc_msg->assn)){
    free_all_address_entries(olsr);
    free_message_tlv(olsr);
    olsr_free_tc_packet(tc_msg);

    return OLSR_FALSE;
  }

  //local interface block
  OLSR_InitList(&tc_msg->local_iface_list);
  tmp_addr_entry = olsr->local_interface_block_entry;
  while(tmp_addr_entry) {
    olsr_ip_copy(olsr, &local_iface_entry.iface_addr, &tmp_addr_entry->ip_addr);
    local_iface_entry.other_if = OLSR_FALSE;

    tlv_entry = tmp_addr_entry->addr_tlv;
    while(tlv_entry) {
      switch(tlv_entry->type){
      case Other_If:
    if(tlv_entry->value == OLSR_TRUE)
      local_iface_entry.other_if = OLSR_TRUE;
    break;
      default:
    break;
      }
      tlv_entry = tlv_entry->next;
    }
    OLSR_InsertList(&tc_msg->local_iface_list, &local_iface_entry,
            sizeof(OLSR_LOCAL_INTERFACE_BLOCK_ENTRY));

    tmp_addr_entry= tmp_addr_entry->next;
  }

  // all mpr selector : advertized by tc
  tc_msg->mpr_selector_address = NULL;
  tc_msg->attached_net_addr = NULL;
  for (i = 0; i < olsr->num_of_addr_tlv_block_entries; ++i){
    tmp_addr_entry = olsr->addr_tlv_block_entries[i];
    tlv_entry = NULL;
    while (tmp_addr_entry){
      //attached network address
      if((tlv_entry = have_attached_network_tlv(tmp_addr_entry->addr_tlv)) != NULL)
    {
      attached_net_entry = (ATTACHED_NETWORK *)olsr_malloc( sizeof(ATTACHED_NETWORK), __FUNCTION__);
      memset(attached_net_entry, 0 , sizeof(ATTACHED_NETWORK));
      attached_net_entry->next = NULL;
      olsr_ip_copy(olsr, &attached_net_entry->network_addr, &tmp_addr_entry->ip_addr);
      attached_net_entry->prefix_length = (olsr_u8_t)tlv_entry->value;

      //queue
      if(tc_msg->attached_net_addr == NULL)
        tc_msg->attached_net_addr = attached_net_entry;
      else{
        attached_net_entry->next = tc_msg->attached_net_addr;
        tc_msg->attached_net_addr = attached_net_entry;
      }
      tmp_addr_entry = tmp_addr_entry->next;
      continue;
    }

      mpr_entry = (struct tc_mpr_addr *)olsr_malloc(sizeof(struct tc_mpr_addr), __FUNCTION__);
      memset(mpr_entry, 0, sizeof(struct tc_mpr_addr));

      olsr_ip_copy(olsr, &mpr_entry->address, &tmp_addr_entry->ip_addr);


      if (tc_msg->mpr_selector_address == NULL){//first
    tc_msg->mpr_selector_address = mpr_entry;
    mpr_entry->next = NULL;
      }else{
    mpr_entry->next = tc_msg->mpr_selector_address;
    tc_msg->mpr_selector_address = mpr_entry;
      }
      tmp_addr_entry = tmp_addr_entry->next;
    }

  }//for

  debug_code(print_tc_message(olsr, tc_msg));
  //free address tlv & message tlv
  free_all_address_entries(olsr);
  free_message_tlv(olsr);

  return OLSR_TRUE;
}

/*
 *
 */

static void
print_tc_message(struct olsrv2 *olsr, struct tc_message *tc)
{
  struct tc_mpr_addr *tmp_mpr_addr = NULL;
  char* paddr = NULL;
  struct olsrd_config *olsr_cnf = olsr->olsr_cnf;
  //check output level
  if (olsr_cnf->debug_level < 3)
    return;

  tmp_mpr_addr = tc->mpr_selector_address;
  olsr_printf("\n*****************************************\n");
  olsr_printf("TC MESSAGE\n\n");
  olsr_printf("Vtime                         %f\n", tc->vtime);

  paddr = olsr_niigata_ip_to_string(olsr, &tc->source_addr);
  olsr_printf("SouceAddr                     %s\n",paddr);
  free(paddr);
  paddr = olsr_niigata_ip_to_string(olsr, &tc->originator);
  olsr_printf("OriginatorAddr                %s\n",paddr);
  free(paddr);

  olsr_printf("MessageSequenceNum            %u\n", tc->message_seq_number);
  olsr_printf("HopCount                      %u\n", tc->hop_count);
  olsr_printf("TTL                           %u\n", tc->ttl);
  olsr_printf("ASSN                          %u\n", tc->assn);
  olsr_printf("******************************************\n\n");
  olsr_printf("MPR Selector\n");
  olsr_printf("-------------------------------------------\n");
  while (tmp_mpr_addr)
    {
    paddr = olsr_niigata_ip_to_string(olsr, &tmp_mpr_addr->address);
    olsr_printf("IP ADDRESS                %s\n",paddr);
    free(paddr);




      olsr_printf("---------------------------------------\n");
      tmp_mpr_addr = tmp_mpr_addr->next;
    }
  olsr_printf("\n\n");

  return;
}


static olsr_bool
process_hello(struct olsrv2 *olsr, struct hello_message *hello,
          union olsr_ip_addr *in_if,
          union olsr_ip_addr *from_addr)
{
  struct hello_neighbor *hello_neigh = NULL;
  OLSR_LIST* retList = NULL;
  OLSR_LIST_ENTRY *entry = NULL;
  OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *local_entry = NULL;
  OLSR_SYMMETRIC_NEIGHBOR_TUPLE *sym_data = NULL;
  olsr_time_t time;
  olsr_bool change_assn = OLSR_FALSE, selected_mpr = OLSR_FALSE;


  //codexxx
	// before processing hello message add the queue length of the corresponding originator to the OLSR_LIST "queue_set"
  olsr_bool IPfound = OLSR_FALSE;
  struct queue_info *queueInf = NULL, *tempo= NULL ;
  OLSR_LIST_ENTRY *queueEntry = NULL; 
  
  queueInf = (queue_info *)olsr_malloc(sizeof(queue_info), __FUNCTION__);
  
  queueInf->orig_IP = hello->orig_addr ;
  queueInf->Qlength = hello->queuelength;
 
  if(olsr->queue_set.numEntry == 0) 
  	{ // insert to the list directly
  	  OLSR_InsertList(&olsr->queue_set,queueInf,sizeof(queue_info));
	  
  }else{ // liste deja contient des element ...donc trouver si deja existe
		
		queueEntry = olsr->queue_set.head ;
		while(queueEntry != NULL)  /////
			{ 
			tempo = (queue_info *)queueEntry->data ;
			if(!cmp_ip_addr(olsr,&tempo->orig_IP,&queueInf->orig_IP)) ////
			{  // on a trouver cet originator IP ds la liste alors update le queue et sortir de la boucle
			   tempo->Qlength = queueInf->Qlength;
			   IPfound = OLSR_TRUE;
			   break;

			}
		queueEntry = queueEntry->next ;
	  }
		
			if(IPfound == OLSR_FALSE)
				{ // cet IP n'existe pas deja dans la liste => l'introduire
				
					 OLSR_InsertList(&olsr->queue_set,queueInf,sizeof(queue_info));
			}
			

	  }
  

  
  //end codexxx


  if (own_ip_addr(olsr, &hello->source_addr))
    { // wiss: ma3neta el source address byetaba2 ma3 wa7ed men el intrface address taba3 node
        if(DEBUG_OLSRV2){
            char* paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
            olsr_printf("Received Hello, but this Hello is sent from ME!!\n[%s]",paddr);
            free(paddr);
        }
      return OLSR_FALSE; // wiss: betla3 men process_hello
    }

  if(search_link_set_local_for_exist(olsr,
                     in_if,
                     &hello->source_addr) == OLSR_FALSE){ // wiss:ma  la2a bel  olsr linkset entry 3enda local_if= "in_if" w neigbor_if=&hello->source_addr 
                     // wiss: ma la2a jar 3endou ip hello->source_addr ma3neta el link da3
    proc_link_set(olsr,
          in_if,
          &hello->source_addr,
          LOST,
          hello->willingness,
          hello->vtime,
          hello->htime);
  }

  // neighbor address
  hello_neigh = hello->neighbors;
  while (hello_neigh){


    if(equal_ip_addr(olsr,
             &hello_neigh->address,
             in_if
             ))
      { // wiss: hello_neigh->address, byetaba2 ma3 in_if
    proc_link_set(olsr,
              in_if,
              &hello->source_addr,
              hello_neigh->status,
              hello->willingness,
              hello->vtime,
              hello->htime);

    //update symmetric neighbor set
    proc_symmetric_neighbor_set(olsr,
                    in_if,
                    hello_neigh->status,
                    hello);
    break; // wiss : so iza fet hon ya3ni la2a el neighbor so break... so iza ma la2an byente2el 3al neigh->next
      }

    hello_neigh = hello_neigh->next;
  }


  //update neighbor address association set
  proc_association_set(olsr, &hello->local_iface_list, hello->vtime);


  hello_neigh = hello->neighbors;
  while (hello_neigh){

    //process 2hop Neighbor set
    proc_2neigh_set(olsr,
            in_if,
            &hello->source_addr,
            &hello_neigh->address,
            hello_neigh->status,
            hello_neigh->other_neigh,
            hello->vtime);

    //check: own interfaces is selected MPR by source nodes.
    if(selected_mpr == OLSR_FALSE &&
       own_ip_addr(olsr, &hello_neigh->address) == OLSR_TRUE &&
       hello_neigh->is_mpr == OLSR_TRUE) {
      selected_mpr = OLSR_TRUE;
    }

    //next pointer
    hello_neigh = hello_neigh->next;
  }

  //update mpr selector set , relay set, advertise neighbor set
  if(selected_mpr == OLSR_TRUE) {
    entry = hello->local_iface_list.head;
    while(entry) {
      local_entry = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)entry->data;
      retList = search_symmetric_neighbor_set(olsr,
                          in_if,
                          &local_entry->iface_addr);

      if(retList) {
    if(retList->numEntry != 1) {
      olsr_error("process_hello():5");
    }
    get_current_time(olsr, &time);
    sym_data = (OLSR_SYMMETRIC_NEIGHBOR_TUPLE *)retList->head->data;
    OLSR_DeleteList_Search(retList);

    if(get_neighbor_status(&time, &sym_data->N_time) == SYMMETRIC) {
        proc_mpr_selector_set(olsr, &local_entry->iface_addr);

        if(olsr->change_mpr_selector_set) {
        if(proc_adv_neigh_set(olsr, &local_entry->iface_addr)){
            proc_relay_set(olsr, &local_entry->iface_addr);
          change_assn = OLSR_TRUE;
          }
      }
    }//if(get_neigh...)
      }

      //next entry
      entry = entry->next;
    }//while
  }
  else{  // wiss: ici selected_mpr==false
    entry = hello->local_iface_list.head;
    while(entry) {
      local_entry = (OLSR_LOCAL_INTERFACE_BLOCK_ENTRY *)entry->data;
      delete_mpr_selector_set(olsr, &local_entry->iface_addr);
      if(olsr->change_mpr_selector_set) {
    delete_adv_neigh_set(olsr, &local_entry->iface_addr);
    if(olsr->change_adv_neigh_set) {
      change_assn = OLSR_TRUE;
      delete_relay_set(olsr, &local_entry->iface_addr);
    }
      }
      //next entry
      entry = entry->next;
    }//while
  }

  /* if I am selecetd as MPR by someone,
     I_am_MPR_flag turns ON and send TC message every TC_INTERVAL */
  if (olsr->I_am_MPR_flag == OLSR_FALSE &&
      olsr->adv_neigh_set.head != NULL){
    olsr->I_am_MPR_flag = OLSR_TRUE;
  }

  if(DEBUG_OLSRV2)
  {
      olsr_printf("\tassn[%d]\n", get_local_assn(olsr));
  }

  if (change_assn == OLSR_TRUE)
    increment_local_assn(olsr);

  return OLSR_TRUE;
}


/*
 *
 */
static olsr_bool
process_tc(struct olsrv2 *olsr, struct tc_message *tc,
       union olsr_ip_addr *in_if
       )
{
  struct tc_mpr_addr *mpr_selector = NULL;
  OLSR_LIST *tmpList = NULL;
  OLSR_LIST_ENTRY *tmpEntry = NULL;
  OLSR_TOPOLOGY_TUPLE *tmpTuple = NULL;
  ATTACHED_NETWORK *attached_net_entry = NULL;
  char* paddr;

  if(DEBUG_OLSRV2)
  {
      olsr_printf("\tProcess TOPOLOGY MESSAGE\n");
  }

/*

//codexxx'
	  // before processing TC message add the queue length of the corresponding originator to the OLSR_LIST "queue_set"
	olsr_bool IPfound = OLSR_FALSE;
	struct queue_info *queueInf = NULL, *tempo= NULL ;
	OLSR_LIST_ENTRY *queueEntry = NULL; 
	
	queueInf = (queue_info *)olsr_malloc(sizeof(queue_info), __FUNCTION__);
	
	queueInf->orig_IP = tc->originator;
	queueInf->Qlength = tc->queuelength;
   
	if(olsr->queue_set.numEntry == 0) 
	  { // insert to the list directly
		OLSR_InsertList(&olsr->queue_set,queueInf,sizeof(queue_info));
		
	}else{ // liste deja contient des element ...donc trouver si deja existe
		  
		  queueEntry = olsr->queue_set.head ;
		  while(queueEntry != NULL)  /////
			  { 
			  tempo = (queue_info *)queueEntry->data ;
			  if(!cmp_ip_addr(olsr,&tempo->orig_IP,&queueInf->orig_IP)) ////
			  {  // on a trouver cet originator IP ds la liste alors update le queue et sortir de la boucle
				 tempo->Qlength = queueInf->Qlength;
				 IPfound = OLSR_TRUE;
				 break;
  
			  }
		  queueEntry = queueEntry->next ;
		}
		  
			  if(IPfound == OLSR_FALSE)
				  { // cet IP n'existe pas deja dans la liste => l'introduire
				  
					   OLSR_InsertList(&olsr->queue_set,queueInf,sizeof(queue_info));
			  }
			  
  
		}
	
  
	
	//end codexxx'






*/





  //13.1.1
  if (lookup_link_status(olsr, &tc->source_addr) != SYMMETRIC)
  {
      if(DEBUG_OLSRV2)
      {
      paddr = olsr_niigata_ip_to_string(olsr, &tc->source_addr);
      olsr_printf("\tsource addr:%s isn't sym neigh\n",paddr);
      free(paddr);
      }
    return OLSR_FALSE;
  }

  //13.1.2
  //check previous :look tc_change_structure
  //13.1.3
  if ((tmpList = lookup_topology_set(olsr, &tc->originator)) != NULL){
    tmpEntry = (OLSR_LIST_ENTRY *)tmpList->head;
    while (tmpEntry)
      {
    tmpTuple = (OLSR_TOPOLOGY_TUPLE *)tmpEntry->data;

    if (tmpTuple->T_seq > tc->assn){
      OLSR_DeleteList_Search(tmpList);

      if(DEBUG_OLSRV2)
      {
          olsr_printf("\t\tThis message is OLD.Skipped\n");
      }
      return OLSR_FALSE;
    }
    tmpEntry = tmpEntry->next;
      }
    OLSR_DeleteList_Search(tmpList);
  }


  //13.1.4
  mpr_selector = tc->mpr_selector_address;
  while (mpr_selector){
      proc_topology_set(olsr, &mpr_selector->address, &tc->originator,
              tc->assn, OLSR_FALSE);
    mpr_selector = mpr_selector->next;
  }

  //updating the attached network set
  attached_net_entry = tc->attached_net_addr;
  while(attached_net_entry){
    proc_attached_set(olsr,
              &attached_net_entry->network_addr,
              attached_net_entry->prefix_length,
              &tc->originator,
              tc->assn);

    attached_net_entry = attached_net_entry->next;
  }
  debug_code(print_attached_set(olsr));

  if(proc_forward_set(olsr, &tc->originator, &tc->source_addr,
              tc->message_seq_number) == OLSR_TRUE){
      forward_message(olsr);
  }

  return OLSR_TRUE;
}

olsr_u8_t get_validity_time_from_hop(struct tlv_tuple *tlv_entry,
                     olsr_u8_t hop_count)
{
  int i = 0;
  olsr_u8_t vtime;
  olsr_u8_t  *p = tlv_entry->extended_value;

  while(i < tlv_entry->length -1)
    {
      vtime = (olsr_u8_t)me_to_double(*p++);
      if(hop_count <= *p++){
      if(DEBUG_OLSRV2)
      {
          olsr_printf("VTIME[%u]\n",vtime);
      }
    return vtime;
      }
      i += 2;
    }
  vtime = (olsr_u8_t)me_to_double(*p);
  if(DEBUG_OLSRV2)
  {
      olsr_printf("VTIME[%u]\n",vtime);
  }
  return vtime;
}
}
