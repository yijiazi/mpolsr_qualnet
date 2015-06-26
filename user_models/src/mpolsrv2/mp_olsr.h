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
#ifndef __MPOLSR_FUNCTIONS__
#define __MPOLSR_FUNCTIONS__

#include "mp_def.h"
#include "mp_proc_m_rtable.h"


#include "mp_olsr_conf.h"
/* for initialize tuples */
#include "mp_olsr_common.h"
#include "mp_olsr_hash_list.h"
#include "mp_olsr_protocol.h"

namespace MPOLSRv2{

struct forward_infomation
{
  OLSR_LIST msg_list;
};


/*
  compatibilities between implementations and qualnet(simulations)
*/

struct olsr_stat{
  unsigned int numMessageSent;
  unsigned int numMessageRecv;
  unsigned int numHelloReceived;
  unsigned int numHelloGenerated;
  unsigned int numTcReceived;
  unsigned int numTcGenerated;
  unsigned int numTcRelayed;
//Change for Long Long Compilation problem
  int_64 sendMsgSize;
  int_64 recvMsgSize;
  //unsigned long long sendMsgSize;
  //unsigned long long recvMsgSize;
  olsr_bool statsPrinted;  // to check whether stat already printed or not
};
/*
typedef struct OLSR_m_rt_entry{
	union olsr_ip_addr * dest;
	union olsr_ip_addr * addr_[123];
}OLSR_m_rt_entry;

//typedef std::multimap<int,int> m_rtable_t;

typedef struct OLSR_m_rtable{
	std::list<int> m_rt_;
	bool out_of_date[123];
} OLSR_M_RTABLE;
*/

struct olsrv2
{
  //def.h
  union olsr_ip_addr main_addr; //exist
  clock_t fwd_timer[MAX_IFS];

  clock_t send_empty_tc;

  //generate_msg.h
  int I_am_MPR_flag;

  //olsr.h
  int changes_neighborhood;
  int changes_topology;
  
  int localqueuelen ;  //codexxx
  

  unsigned short seed[3];

  olsr_u16_t message_seqno;
  olsr_u16_t packet_seqno;


#define MAX_ADDR_TLV_BLOCK_ENTRIES  100
  int num_of_local_interface_block_entry;
  struct address_tuple *local_interface_block_entry;
  struct address_tuple *addr_tlv_block_entries[MAX_ADDR_TLV_BLOCK_ENTRIES];
  int num_of_addr_tlv_block_entries;

  //parse_msg.h
  struct parse_function_entry *parse_functions;
  struct packet_header packet_header;
  struct message_header message_header;
  char* message_body;
  size_t message_body_size;

  //parse_tlv.h
  struct tlv_tuple *message_tlv_entry;

  //proc_2neigh_set.h
  OLSR_HASH_LIST two_neigh_set[HASHSIZE];
  olsr_bool change_two_neigh_set;

  //proc_adv_neigh_set.h
  OLSR_LIST adv_neigh_set;
  olsr_bool change_adv_neigh_set;

  //proc_associ_set.h
  OLSR_HASH_LIST associ_set[HASHSIZE];
  olsr_bool change_associ_set;

  //proc_forward_set.h
  OLSR_HASH_LIST forward_set[HASHSIZE];
  olsr_bool change_forward_set;

  //proc_link_set.h
  OLSR_LIST link_set;
  olsr_bool change_link_set;

  OLSR_LIST queue_set ; //codexxx

  //proc_mpr_selector_set.h
  OLSR_LIST mpr_selector_set;
  olsr_bool change_mpr_selector_set;

  //proc_mpr_set.h
  OLSR_LIST mpr_set;
  olsr_bool change_mpr_set;

  //proc_rcv_msg_set.h
  OLSR_HASH_LIST rcv_msg_set[HASHSIZE];
  olsr_bool change_rcv_msg_set;

  //proc_proc_set.h
  OLSR_HASH_LIST proc_set[HASHSIZE];
  olsr_bool change_proc_set;

  //proc_relay_set.h
  OLSR_LIST relay_set;
  olsr_bool change_relay_set;
  olsr_u16_t assn;

  //proc_routing_set.h
  OLSR_HASH_LIST routing_set[HASHSIZE];
  OLSR_HASH_LIST routing_set_new[HASHSIZE];
  OLSR_HASH_LIST routing_set_old[HASHSIZE];

  //proc_topology_set.h
  OLSR_HASH_LIST topology_set[HASHSIZE];
  olsr_bool change_topology_set;

  OLSR_LIST attached_set;
    olsr_bool change_attached_set;

  OLSR_LIST assn_history_set;
  olsr_bool change_assn_history_set;

  OLSR_HASH_LIST sym_neigh_set[HASHSIZE];
  olsr_bool change_sym_neigh_set;


  struct olsr_stat stat;


  olsr_time_t current_sim_time;
  olsr_u8_t iface_num;
  union olsr_ip_addr *iface_addr;
  struct forward_infomation* forward_info;
  unsigned char parsingIfNum;

  ATTACHED_NETWORK *attached_net_addr;
  olsr_u32_t advNetAddrNum;

  struct olsrd_config* olsr_cnf;
  //for qualnet config
  OLSRv2QualConf *qual_cnf;
  olsr_u8_t* interfaceMappingOlsr;
  olsr_u8_t* interfaceMappingQualnet;

  //for multipath
  OLSR_M_RTABLE* m_rtable;
  int pathCounter; //the path counter for round-robin

  struct memory_list *memlst;
  void** forwardMsg;
};

void olsr_reconfigure(int signum);

#if defined __cplusplus
//extern "C"
//{
#endif

  void olsr_init_tuples(struct olsrv2 *);
  void init_msg_seqno(struct olsrv2 *);
  void init_packet_seqno(struct olsrv2 *);
  olsr_u16_t get_packet_seqno(struct olsrv2 *);
  void olsr_process_changes(struct olsrv2 *);
  void olsr_check_timeout_tuples(struct olsrv2 *);


  void init_forward_infomation(struct olsrv2 *);
  olsr_bool check_forward_infomation(struct olsrv2 *, unsigned char);

#if defined __cplusplus
//}
#endif

//inline
olsr_u16_t get_msg_seqno(struct olsrv2 *);

void forward_message(struct olsrv2 *);

void set_buffer_timer(struct olsrv2*, void *);

void olsr_init_tables(void);

void olsr_init_willingness(void);

void olsr_update_willingness(void *);

olsr_u8_t olsr_calculate_willingness(void);

void olsr_exit(const char *, int);

void *olsr_malloc(size_t size, const char *id);


static
inline
olsr_u32_t
olsr_hashing(struct olsrv2* olsr, const union olsr_ip_addr *address)
{
  olsr_u32_t hash;
  const char *tmp = (const char *)address;

  if(olsr->olsr_cnf->ip_version == AF_INET)
    /* IPv4 */
    hash = tmp[3];
  else
    {
      /* IPv6 */
      hash = tmp[15];
    }

  hash &= HASHMASK;

  return hash;
}
}

#endif
