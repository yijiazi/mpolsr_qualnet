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

#include <stdarg.h>
#include <signal.h>
#include <assert.h>
#include "mp_def.h"
#include "mp_olsr.h"
#include "mp_olsr_util.h"
#include "mp_olsr_common.h"
#include "mp_proc_rcv_msg_set.h"
#include "mp_proc_proc_set.h"
#include "mp_proc_relay_set.h"
#include "mp_proc_forward_set.h"
#include "mp_proc_link_set.h"
#include "mp_proc_2neigh_set.h"
#include "mp_proc_topology_set.h"
#include "mp_proc_adv_neigh_set.h"
#include "mp_proc_assn_history_set.h"
#include "mp_proc_attach_network_set.h"
#include "mp_proc_routing_set.h"
#include "mp_proc_mpr_set.h"
#include "mp_proc_mpr_selector_set.h"
#include "mp_proc_neighbor_address_association_set.h"
#include "mp_proc_symmetric_neighbor_set.h"
#include "mp_proc_m_rtable.h"

#include "mp_address_compress.h"
#include "mp_generate_msg.h"
#include "mp_parse_address.h"
#include "mp_parse_tlv.h"

namespace MPOLSRv2{

extern int random(struct olsrv2 *olsr);


//WIN FIX: Added all global variables here

/*
 * Global olsrd configuragtion
 */

// struct olsrd_config *olsr_cnf; //Removing-Globalo-Variables

/* Global tick resolution */
olsr_u16_t system_tick_divider;

int exit_value; /* Global return value for process termination */


/* Timer data */
clock_t now_times;              /* current idea of times(2) reported uptime */
//struct timeval now;       /* current idea of time */
//struct tm *nowtm;     /* current idea of time (in tm) */

olsr_bool disp_pack_in;         /* display incoming packet content? */
olsr_bool disp_pack_out;        /* display outgoing packet content? */

olsr_bool del_gws;

/*
 * Timer values
 */

float will_int;
float max_jitter;

//size_t ipsize;  Removed

/* OLSR UPD port */
int olsr_udp_port;

/* The socket used for all ioctls */
int ioctl_s;

/* routing socket */
#if defined __FreeBSD__ || defined __MacOSX__ || defined __NetBSD__
int rts;
#endif

float max_tc_vtime;

clock_t fwdtimer[MAX_IFS];  /* forwarding timer */

int minsize;

//olsr_bool changes;                /* is set if changes occur in MPRS set */

/* TC empty message sending */
//clock_t send_empty_tc;

//End WIN FIX


void
init_msg_seqno(struct olsrv2 *olsr)
{
  //struct olsrv2
  olsr->message_seqno = (olsr_u16_t)(random(olsr) & 0xFFFF);
}

//inline
olsr_u16_t
get_msg_seqno(struct olsrv2 *olsr)
{
  return olsr->message_seqno++;
}

void
init_packet_seqno(struct olsrv2 *olsr)
{
  //struct olsrv2
  olsr->packet_seqno = (olsr_u16_t)(random(olsr) & 0xFFFF);
}


olsr_u16_t
get_packet_seqno(struct olsrv2 *olsr)
{
  return olsr->packet_seqno++;
}


static void
flash_change_flags(struct olsrv2 *olsr)
{
  olsr->change_two_neigh_set = OLSR_FALSE;
  olsr->change_link_set = OLSR_FALSE;
  olsr->change_topology_set = OLSR_FALSE;
  olsr->change_mpr_selector_set = OLSR_FALSE;

  /* Not need to change routing calculation */
  olsr->change_associ_set = OLSR_FALSE;
  olsr->change_forward_set = OLSR_FALSE;

  olsr->change_proc_set = OLSR_FALSE;
  olsr->change_rcv_msg_set = OLSR_FALSE;
  olsr->change_relay_set = OLSR_FALSE;
  olsr->change_adv_neigh_set = OLSR_FALSE;
  olsr->change_attached_set = OLSR_FALSE;
}


static void
init_stats(struct olsrv2* olsr)
{
  olsr->stat.numMessageSent = 0;
  olsr->stat.numMessageRecv = 0;
  olsr->stat.numHelloReceived = 0;
  olsr->stat.numHelloGenerated = 0;
  olsr->stat.numTcReceived = 0;
  olsr->stat.numTcGenerated = 0;
  olsr->stat.numTcRelayed = 0;
  olsr->stat.sendMsgSize = 0;
  olsr->stat.recvMsgSize = 0;
  olsr->stat.statsPrinted = OLSR_FALSE;
}


void
olsr_init_tuples(struct olsrv2 *olsr)
{
  olsr->changes_topology = OLSR_FALSE;
  olsr->changes_neighborhood = OLSR_FALSE;

  flash_change_flags(olsr);

  init_rcv_msg_set(olsr);
  init_proc_set(olsr);
  init_relay_set(olsr);
  init_forward_set(olsr);
  init_link_set(olsr);
  init_2neigh_set(olsr);
  init_topology_set(olsr);
  init_routing_set(olsr);
  init_mpr_set(olsr);
  init_mpr_selector_set(olsr);
  init_stats(olsr);
  init_symmetric_neighbor_set(olsr);
  
  init_m_rtable(olsr);

  init_association_set(olsr);
  init_adv_neigh_set(olsr);
  init_relay_set(olsr);
  init_assn_history_set(olsr);
  init_attached_set(olsr);
}

static void
olsr_check_changes(struct olsrv2 *olsr)
{
  if (olsr->change_adv_neigh_set == OLSR_TRUE &&
      olsr->adv_neigh_set.head == NULL &&
      olsr->attached_net_addr == NULL)
    {
        //I should send additional TC message, now!
    //but that code will write later.
    olsr->I_am_MPR_flag = OLSR_FALSE;
    }
  if(olsr->change_adv_neigh_set)
    {
    increment_local_assn(olsr);
        if (DEBUG_OLSRV2){
            olsr_printf("Increase ASSN number to %d.\n", olsr->assn);
        }
    }

  //struct olsrv2
  if (olsr->change_two_neigh_set == OLSR_TRUE ||
      olsr->change_link_set == OLSR_TRUE)
    {
      olsr->changes_neighborhood = OLSR_TRUE;
    }
  if (olsr->change_topology_set == OLSR_TRUE ||
      olsr->change_attached_set == OLSR_TRUE)
    {
      olsr->changes_topology = OLSR_TRUE;
    }

  flash_change_flags(olsr);
}


/**
 *
 *
 *
 */
void
olsr_process_changes(struct olsrv2 *olsr)
{

  olsr_check_changes(olsr);

  //struct olsrv2
  if (olsr->changes_neighborhood)
  {
      if(DEBUG_OLSRV2)
      {
          olsr_printf("CHANGES IN NEIGHBORHOOD\n");
      }
  }
  if (olsr->changes_topology)
  {
      if(DEBUG_OLSRV2)
      {
      olsr_printf("CHANGES IN TOPOLOGY\n");
      }
  }


  if (!olsr->changes_neighborhood &&
      !olsr->changes_topology)
  {
      return;
  }

  if (olsr->changes_neighborhood)
  {
      /* Calculate new mprs*/
      proc_mpr_set(olsr);
	  
//      proc_routing_set(olsr); 
//for multipath routing, just set the out_of_date flag
	  set_flag(olsr,true);

      add_attached_network_set(olsr);
  }

  else if (olsr->changes_topology)
  {
  //    proc_routing_set(olsr);
  //for multipath routing, just set the out_of_date flag
  		set_flag(olsr,true);
      add_attached_network_set(olsr);
  }


  if (DEBUG_OLSRV2 && olsr->olsr_cnf->debug_level > 1)
  {
      if (olsr->olsr_cnf->debug_level > 2)
      {
      print_mpr_set(olsr);
      if (olsr->olsr_cnf->debug_level > 3)
      {
          print_rcv_msg_set(olsr);
          print_proc_set(olsr);
          print_forward_set(olsr);
          //print_associ_set(olsr);
      }
      }

      print_link_set(olsr);
      olsr_printf("\n");
      print_symmetric_neighbor_set(olsr);
      olsr_printf("\n");
      print_2neigh_set(olsr);
      olsr_printf("\n");
      print_association_set(olsr);
      olsr_printf("\n");
      print_mpr_selector_set(olsr);
      olsr_printf("\n");
      print_adv_neigh_set(olsr);
      olsr_printf("\n");
      print_relay_set(olsr);
      olsr_printf("\n");
      print_topology_set(olsr);
      olsr_printf("\n");
     // print_routing_set(olsr);
     // olsr_printf("\n");

  }

  return;
}

void
set_buffer_timer(struct olsrv2* olsr ,
         void *ifn)
{
  float jitter;

  /* Set timer */
  jitter = (float)random(olsr) / RAND_MAX;
  jitter *= max_jitter;
}

void
olsr_exit(const char *msg, int val)
{
  fflush(stdout);
  exit_value = val;
  olsr_printf("%s",msg);
  raise(SIGTERM);
}


void *
olsr_malloc(size_t size, const char *id)
{
  void *ptr = NULL;

  if (size > 0 )                     //Zero byte memory allocation fix
  {
      if ((ptr = malloc(size)) == 0)
        {
          olsr_exit((char *)id, EXIT_FAILURE);
        }
//Added for Solaris mismatch
  memset(ptr, 0, size);
//Added for Solaris mismatch
  }
  return ptr;
}

static void
set_forward_infomation(struct olsrv2 *olsr,
               olsr_u8_t *msg,
               olsr_u32_t msg_size,
               unsigned char index)
{
  OLSR_InsertList(&olsr->forward_info[index].msg_list, msg, msg_size);
}

void
init_forward_infomation(struct olsrv2 *olsr, unsigned char index)
{
  OLSR_DeleteList_Static(&olsr->forward_info[index].msg_list);
  assert(olsr->forward_info[index].msg_list.head == NULL);
}

olsr_bool
check_forward_infomation(struct olsrv2 *olsr, unsigned char index)
{
  return (olsr_bool)(olsr->forward_info[index].msg_list.head != NULL);
}


void
forward_message(struct olsrv2 *olsr)
{
  const struct message_header* m_header = &olsr->message_header;
  olsr_pktbuf_t* msg = NULL;

  msg = olsr_pktbuf_alloc();
  olsr_pktbuf_clear(msg);

  /* TC should be forwarded all interface.
     but now, we forward only one interface.
     I'll correct later...  */
  build_message_header(olsr, msg, (olsr_u16_t)olsr->message_body_size,
      m_header->message_type,
      &m_header->orig_addr, m_header->ttl - 1, m_header->hop_count + 1,
      m_header->message_seq_num);


  if (m_header->message_type == TC_MESSAGE){
      olsr->stat.numTcRelayed++;
      if (DEBUG_OLSRV2){
        olsr_printf("Increment TC relayed to %d.\n",olsr->stat.numTcRelayed);
      }
  }

  olsr_pktbuf_append_byte_ary(msg, (olsr_u8_t* )olsr->message_body, olsr->message_body_size);


  if (DEBUG_OLSRV2){
      olsr_printf("TTL:%d\nhopcount:%d\nmsg_size:%d\n",m_header->ttl - 1,
                                    m_header->hop_count + 1, (int)msg->len);
  }

  if (m_header->message_type == TC_MESSAGE)
  {
      int ifNum;

      for(ifNum=0; ifNum<olsr->iface_num; ifNum++)
      {
      set_forward_infomation(olsr, msg->data, (unsigned int)msg->len,
          (unsigned char)ifNum);
      }
  }
  else
  {
      set_forward_infomation(olsr, msg->data, (unsigned int)msg->len,
          olsr->parsingIfNum);
  }

  olsr_pktbuf_free(&msg);
}

void
olsr_check_timeout_tuples(struct olsrv2 *olsr)
{
  OLSR_LIST* retList = NULL;

  // check each tuple entry should be deleted.
  /* Most important changes */
  delete_2neigh_set_for_timeout(olsr);  //change_two_neigh_set
  delete_link_set_for_timeout(olsr);    //change_link_set
  delete_symmetric_neighbor_set_for_timeout(olsr);
  if(OLSR_LINK_METRIC == OLSR_TRUE)
  {
      check_link_hysteresis(olsr);
  }

  delete_topology_set_for_timeout(olsr);    //change_topology_set
  //delete_relay_set_for_timeout(olsr); //change_relay_set
  /* if the relay set is timeout, then
     check that I should be staying as MPR or not. */


  retList = delete_mpr_selector_set_for_linkbreakage(olsr);
  if(retList)
  {
      delete_adv_neigh_set_handler_for_ms_timeout(olsr, retList);
      delete_relay_set_handler_for_ms_timeout(olsr, retList);
      OLSR_DeleteList(retList);
  }


  retList = delete_mpr_selector_set_for_timeout(olsr);
  if(retList){
    //assert(!olsr->change_adv_neigh_set);
    delete_adv_neigh_set_handler_for_ms_timeout(olsr, retList);
    delete_relay_set_handler_for_ms_timeout(olsr, retList);
    OLSR_DeleteList(retList);
  }

  delete_attached_set_for_timeout(olsr);
  delete_assn_history_set_for_timeout(olsr);
  /* Not need to change routing calculation */
  delete_association_set_for_timeout(olsr);
  //delete_associ_set_for_timeout(olsr);    //change_associ_set
  delete_forward_set_for_timeout(olsr); //change_forward_set
  delete_proc_set_for_timeout(olsr);    //change_proc_set
  delete_rcv_msg_set_for_timeout(olsr); //change_rcv_msg_set
}
}
