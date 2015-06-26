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
//qualnet
#include "api.h"
#include "app_util.h"
#include "network_ip.h"
#include "ipv6.h"
#include "ipv6_route.h"
#include "random.h"

//Fix for Solaris compilation
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
    #ifndef _NETINET_IN_H
    #define _NETINET_IN_H
    #endif
#endif

//olsrv2_niigata 
#include "mp_proc_rcv_msg_set.h"
#include "mp_proc_proc_set.h"
#include "mp_proc_relay_set.h"
#include "mp_proc_forward_set.h"
#include "mp_proc_link_set.h"
#include "mp_proc_2neigh_set.h"
#include "mp_proc_topology_set.h"
#include "mp_proc_adv_neigh_set.h"
#include "mp_proc_routing_set.h"
#include "mp_proc_mpr_set.h"
#include "mp_proc_mpr_selector_set.h"
#include "mp_proc_attach_network_set.h"
#include "mp_proc_assn_history_set.h"
#include "mp_proc_neighbor_address_association_set.h"
#include "mp_generate_msg.h"
#include "mp_parse_msg.h"

#include "mp_olsr_types.h"
#include "mp_olsr_debug.h"
#include "mpolsrv2/mp_olsr_conf.h"
#include "mp_olsr_util.h"
#include "mp_olsr_list.h"
#include "mpolsrv2/mp_olsr.h" 
#include "mp_pktbuf.h"
#include "mp_proc_symmetric_neighbor_set.h"
#include "mp_olsr_multipath.h"
#include "mp_proc_m_rtable.h"

#include "mp_olsr_util_inline.h"
//#include "olsr.h"


#include "mp_routing_olsrv2_niigata.h"



namespace MPOLSRv2{

#define MAXMESSAGESIZE      1500



#define DEBUG_OUTPUT 0
//#define DEBUG_OUTPUT 1

int random(struct olsrv2 *olsr)
{

    return (RANDOM_nrand(olsr->seed) % 32767);
}


static void
RoutingOLSRv2_Niigata_DumpPacket(char *packet, olsr_u16_t size)
{
  int i;
  char *p = NULL;
  if(DEBUG_OLSRV2){
      olsr_printf("Dump packet of size = %d\n",size);
  }
  p = packet;
  for(i = 0 ; i < size ; i++){
    if(i%4==0)
      olsr_printf("\n");
    olsr_printf("%3d\t",(olsr_u8_t)*p);
    p++;
  }
}

/* Shift to olsr_conf.cpp for MAC mismatch
MACHINE_TYPE GetMachineType()
{
    union type{
        char a;
        int b;
    }m_type;

    m_type.b = 0xff;

    if (m_type.a == 0)
    {
    return B_ENDIAN;
    }
    else
    {
    return L_ENDIAN;
    }
}*/

static void
RoutingOLSRv2_Niigata_RotateShiftByte(olsr_u8_t *data, olsr_u16_t size)
{
    if (GetMachineType()== B_ENDIAN)
    {
    return;
    }

    olsr_u8_t *buf = NULL; 

    assert(size > 0);
    buf = (olsr_u8_t *)MEM_malloc(size);
    memset(buf, 0, size);
    memcpy(buf, data, size);

    for(int i=0; i<size; i++)
    {
    data[i] = buf[size-i-1];
    }
    MEM_free(buf);
}

static Address*
RoutingOLSRv2_Niigata_GetQualnetAddress(struct olsrv2 *olsr, union olsr_ip_addr olsrv2_niigata)
{
    olsrd_config* olsr_cnf = olsr->olsr_cnf;


    Address* qualnet_addr = (Address*)MEM_malloc(sizeof(Address));
    memset(qualnet_addr, 0, sizeof(Address));


    if(olsr_cnf->ip_version == AF_INET){
    qualnet_addr->networkType = NETWORK_IPV4;
    memcpy(&qualnet_addr->interfaceAddr.ipv4,
           &olsrv2_niigata.v4, olsr_cnf->ipsize);
    RoutingOLSRv2_Niigata_RotateShiftByte
        ((olsr_u8_t *)&qualnet_addr->interfaceAddr.ipv4,
        (olsr_u16_t)olsr_cnf->ipsize);
    }else{
//    qualnet_addr->networkType = NETWORK_IPV6;
//    memcpy(&qualnet_addr->interfaceAddr.ipv6.s6_addr,
//           olsrv2_niigata.v6.s6_addr, olsr_cnf->ipsize);
	printf("for IPv6 commented for compatible with qualnet 5.0. please modify if needed, by Jiazi");
	exit(0);
    }

    return qualnet_addr;
}

static union olsr_ip_addr*
RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(struct olsrv2 *olsr, Address qualnet_addr)
{
    olsrd_config* olsr_cnf = olsr->olsr_cnf;

    union olsr_ip_addr* olsrv2_niigata =
    (olsr_ip_addr*)MEM_malloc(sizeof(union olsr_ip_addr));
    memset(olsrv2_niigata, 0, sizeof(union olsr_ip_addr));

    if(qualnet_addr.networkType == NETWORK_IPV4){
    memcpy(&olsrv2_niigata->v4,
           &qualnet_addr.interfaceAddr.ipv4,
           olsr_cnf->ipsize);
    RoutingOLSRv2_Niigata_RotateShiftByte
      ((olsr_u8_t *)&olsrv2_niigata->v4, (olsr_u16_t) olsr_cnf->ipsize);

    }else{
    memcpy(&olsrv2_niigata->v6.s6_addr_8,
           &qualnet_addr.interfaceAddr.ipv6.s6_addr, olsr_cnf->ipsize);
    }

    return olsrv2_niigata;
}

static
olsr_u8_t * //new_msg
RoutingOLSRv2_Niigata_AddPacketHeader(Node *node,
                      olsr_u8_t *msg,
                      olsr_u32_t msg_size,
                      olsr_u32_t *new_msg_size)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  olsr_u8_t *new_msg = NULL;
  struct packet_header *p_header = NULL;

  *new_msg_size = msg_size + sizeof(struct packet_header);
  new_msg = (olsr_u8_t *)MEM_malloc(*new_msg_size);

  p_header = (struct packet_header *)new_msg;
  p_header->packet_seq_num = get_packet_seqno(olsr);
  p_header->zero = 0;
  p_header->packet_semantics =0;

  RoutingOLSRv2_Niigata_RotateShiftByte((olsr_u8_t *)&p_header->zero,
                    sizeof(olsr_u8_t));
  RoutingOLSRv2_Niigata_RotateShiftByte((olsr_u8_t *)&p_header->packet_semantics,
                    sizeof(olsr_u8_t));
  RoutingOLSRv2_Niigata_RotateShiftByte((olsr_u8_t *)&p_header->packet_seq_num,
                    sizeof(olsr_u16_t));
  new_msg += sizeof(struct packet_header);

  memcpy(new_msg, msg, msg_size);

  new_msg -= sizeof(struct packet_header);

  return new_msg;
}

static
olsr_u8_t *
RoutingOLSRv2_Niigata_EncapsulateMessage(Node *node,
                     olsr_u8_t *msg,
                     olsr_u32_t msg_size,
                     olsr_u32_t *new_msg_size,
                     unsigned char index)
{
    struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

    olsr_u8_t* buf = (olsr_u8_t*)MEM_malloc(MAXMESSAGESIZE);
    memset(buf, 0, MAXMESSAGESIZE);

    olsr_u8_t* buf_ptr = buf;
    olsr_u32_t extra_size = 0;

    *new_msg_size = 0;

    if(msg != NULL && msg_size > 0){
    if(msg_size % 4 != 0)
    {
        extra_size = 4 - (msg_size % 4);
    }
    if((msg_size  + extra_size + sizeof(struct packet_header)) <= MAXMESSAGESIZE)
    {
        *new_msg_size = *new_msg_size + msg_size + extra_size;
        memcpy(buf_ptr, msg, msg_size);
        buf_ptr = buf_ptr +(msg_size + extra_size);
    }
    } //wiss: end of : msg != NULL && msg_size > 0

    if(check_forward_infomation(olsr, index))
    {
    OLSR_LIST_ENTRY *tmp = NULL, *del = NULL;

    tmp = olsr->forward_info[index].msg_list.head;
    while(tmp)
    {
        extra_size = 0;
        if(tmp->size % 4 != 0)
        {
        extra_size = 4 - (tmp->size % 4);
        }
        if((*new_msg_size + tmp->size + extra_size + sizeof(struct packet_header)) <=  MAXMESSAGESIZE)
        {
        *new_msg_size = *new_msg_size + (tmp->size + extra_size);

        memcpy(buf_ptr, tmp->data, tmp->size);
        buf_ptr += tmp->size + extra_size;

        del = tmp;
        tmp = tmp->next;

        OLSR_DeleteListEntry(&olsr->forward_info[index].msg_list, del);
        }
        else
        {
        tmp = tmp->next;
        }
    }
    }

    //setting value of *buf_ptr to NULL before leaving
    buf_ptr = NULL;

    return buf;
}

static void
RoutingOLSRv2_Niigata_Send(Node *node,
               olsr_u8_t *msg,
               olsr_u32_t packetsize,
               clocktype delay,
               unsigned char index)
{
    struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;
    olsrd_config* olsr_cnf = olsr->olsr_cnf;

    olsr_u8_t *new_msg = NULL;
    olsr_u32_t new_msg_size = 0;

    new_msg = RoutingOLSRv2_Niigata_AddPacketHeader(node,
                            msg,
                            packetsize,
                            &new_msg_size);

    NetworkType networkType;

    if (olsr_cnf->ip_version == AF_INET) {
        networkType = NETWORK_IPV4;
    }
    else
    {
        networkType = NETWORK_IPV6;
    }

    if ((NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
    == ROUTING_PROTOCOL_OLSRv2_NIIGATA)||(NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
    == ROUTING_PROTOCOL_MPOLSRv2_NIIGATA))
    {
    if(olsr_cnf->ip_version == AF_INET)
    {
        APP_UdpSendNewDataWithPriority(node,
                       APP_ROUTING_MPOLSRv2_NIIGATA,
                       NetworkIpGetInterfaceAddress(node, index),
                       APP_ROUTING_MPOLSRv2_NIIGATA,
                       ANY_DEST,
                       index,
                       (char *) new_msg,
                       new_msg_size,
                       IPTOS_PREC_INTERNETCONTROL,
                       delay,
                       TRACE_OLSRv2_NIIGATA);
    }
    else
    {
        Address source_address, any_addr;

        source_address.networkType = NETWORK_IPV6;
        NetworkGetInterfaceInfo(node, index, &source_address, NETWORK_IPV6);

        //Multicast Cast address (ff0e::1)
        /*
          any_addr.networkType = NETWORK_IPV6;
          any_addr.interfaceAddr.ipv6.s6_addr32[0] = 3839;
          any_addr.interfaceAddr.ipv6.s6_addr32[1] = 0;
          any_addr.interfaceAddr.ipv6.s6_addr32[2] = 0;
          any_addr.interfaceAddr.ipv6.s6_addr32[3] = 16777216;
        */

        any_addr.interfaceAddr.ipv6.s6_addr8[0] = 0xff;
        any_addr.interfaceAddr.ipv6.s6_addr8[1] = 0x0e;
        any_addr.interfaceAddr.ipv6.s6_addr8[2] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[3] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[4] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[5] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[6] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[7] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[8] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[9] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[10] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[11] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[12] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[13] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[14] = 0x00;
        any_addr.interfaceAddr.ipv6.s6_addr8[15] = 0x01;
        any_addr.networkType = NETWORK_IPV6;

        APP_UdpSendNewDataWithPriority(node,
                       APP_ROUTING_MPOLSRv2_NIIGATA,
                       source_address,
                       APP_ROUTING_MPOLSRv2_NIIGATA,
                       any_addr,
                       index,
                       (char *) new_msg,
                       new_msg_size,
                       IPTOS_PREC_INTERNETCONTROL,
                       delay,
                       TRACE_OLSRv2_NIIGATA);


    }

    olsr->stat.numMessageSent++;
    if(DEBUG_OLSRV2)
    {
        olsr_printf("Increment Message Send Count to %d.\n", olsr->stat.numMessageSent);
    }
    olsr->stat.sendMsgSize += new_msg_size;
    if(DEBUG_OLSRV2)
    {
        olsr_printf("Increment Message Size Count %lld.\n", olsr->stat.sendMsgSize);
    }
    }//if routing protocol olsrv2

    MEM_free(new_msg);
}

static void
RoutingOLSRv2_Niigata_ForwardMessage(Node *node, unsigned char index)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  olsr_u8_t *encapsulated_msg = NULL;
  olsr_u32_t encapsulated_msg_size = 0;
  clocktype jitter;

  if(check_forward_infomation(olsr, olsr->interfaceMappingQualnet[index])){

    encapsulated_msg =
      RoutingOLSRv2_Niigata_EncapsulateMessage(node,
                           NULL,
                           0,
                           &encapsulated_msg_size,
                           olsr->interfaceMappingQualnet[index]);


    jitter = (clocktype) (RANDOM_nrand(olsr->seed) %
              (clocktype) olsr->qual_cnf->max_hello_jitter);

    RoutingOLSRv2_Niigata_Send(node,
                   encapsulated_msg,
                   encapsulated_msg_size,
                   jitter,
                   index);

    MEM_free(encapsulated_msg);
  }
}

static void
RoutingOLSRv2_Niigata_GenerateHelloMessage(Node *node,
                       clocktype helloInterval,
                       unsigned char index)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  Message    *helloPeriodicMsg = NULL;
  olsr_u8_t *encapsulated_msg = NULL;
  olsr_u32_t encapsulated_msg_size = 0;
  clocktype jitter;
  olsr_pktbuf_t *pktbuf = NULL;
//wiss: initialize buffer
  pktbuf = olsr_pktbuf_alloc();
  olsr_pktbuf_clear(pktbuf);

  if(DEBUG_OLSRV2)
  {
      olsr_printf("Going to build Hello Message.\n");
  }

  build_hello_msg(olsr, pktbuf, &olsr->iface_addr[olsr->interfaceMappingQualnet[index]]);

  olsr->stat.numHelloGenerated++;

  if(DEBUG_OLSRV2)
  {
      olsr_printf("Increment Hello Count to %d.\n",olsr->stat.numHelloGenerated);
  }
  encapsulated_msg =
    RoutingOLSRv2_Niigata_EncapsulateMessage(node,
                         pktbuf->data,
                         (olsr_u32_t)pktbuf->len,
                         &encapsulated_msg_size,
                         olsr->interfaceMappingQualnet[index]);  // wiss: haydi return buff

  jitter = (clocktype) (RANDOM_nrand(olsr->seed) %
            (clocktype) olsr->qual_cnf->max_hello_jitter);

  //send hello message
  RoutingOLSRv2_Niigata_Send(node,
                 encapsulated_msg,
                 encapsulated_msg_size,
                 jitter,
                 index);

  //set next event
  helloPeriodicMsg = MESSAGE_Alloc(node,
                   APP_LAYER,
                   APP_ROUTING_MPOLSRv2_NIIGATA,
                   MSG_APP_OLSRv2_NIIGATA_PeriodicHello);

  MESSAGE_InfoAlloc(node, helloPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(helloPeriodicMsg) = index;

  MESSAGE_Send(node, helloPeriodicMsg, helloInterval);

  MEM_free(encapsulated_msg);
  olsr_pktbuf_free(&pktbuf);
}

static void
RoutingOLSRv2_Niigata_GenerateTcMessage(Node *node,
                    clocktype tcInterval,
                    unsigned char index)
{
  struct olsrv2 *olsr =
      (struct olsrv2 *)node->appData.olsrv2;

  Message    *tcPeriodicMsg = NULL;
  olsr_u8_t *encapsulated_msg = NULL;
  olsr_u32_t  encapsulated_msg_size = 0;
  olsr_pktbuf_t *pktbuf = NULL;
  clocktype jitter;

  jitter = (clocktype) (RANDOM_nrand(olsr->seed) %
            (clocktype) olsr->qual_cnf->max_tc_jitter);

  if(olsr->I_am_MPR_flag){
  //if(olsr->adv_neigh_set.head != NULL){
      pktbuf = olsr_pktbuf_alloc();
      olsr_pktbuf_clear(pktbuf);   // wiss: initialisation

      if(DEBUG_OLSRV2){
      olsr_printf("Going to build TC Message.\n");
      }
      build_tc_msg(olsr, pktbuf, &olsr->iface_addr[olsr->interfaceMappingQualnet[index]]);
      olsr->stat.numTcGenerated++;

      if(DEBUG_OLSRV2){
      olsr_printf("Increment TC Count to %d.\n",olsr->stat.numTcGenerated);
      }

      encapsulated_msg =
      RoutingOLSRv2_Niigata_EncapsulateMessage(node,
                           pktbuf->data,
                           (olsr_u32_t)pktbuf->len,
                           &encapsulated_msg_size,
                           olsr->interfaceMappingQualnet[index]);

      //send tc message
      RoutingOLSRv2_Niigata_Send(node,
                 encapsulated_msg,
                 encapsulated_msg_size,
                 jitter,
                 index);

      MEM_free(encapsulated_msg);
      olsr_pktbuf_free(&pktbuf);

  }

  //set next event  wiss: pour les fois prochaine...comme un timer
  tcPeriodicMsg = MESSAGE_Alloc(node,
                APP_LAYER,
                APP_ROUTING_MPOLSRv2_NIIGATA,
                MSG_APP_OLSRv2_NIIGATA_PeriodicTc);

  MESSAGE_InfoAlloc(node, tcPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(tcPeriodicMsg) = index;

  MESSAGE_Send(node, tcPeriodicMsg, tcInterval);
}

static void
RoutingOLSRv2_Niigata_InitQualnetRoute(Node *node)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;
  olsrd_config* olsr_cnf = olsr->olsr_cnf;
  int hash_index;

  Address* dest_addr = NULL;
  Address* next_addr = NULL;
  Address* i_addr = NULL;


  if(olsr_cnf->ip_version == AF_INET)
  {
      NetworkEmptyForwardingTable(node, ROUTING_PROTOCOL_OLSRv2_NIIGATA);
  }
  else
  {
      OLSR_LIST_ENTRY *tmp = NULL;
      OLSR_ROUTING_TUPLE *data = NULL;

      for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
      {
      tmp = olsr->routing_set_old[hash_index].list.head;
      while(tmp)
      {
          data = (OLSR_ROUTING_TUPLE *)tmp->data;
          dest_addr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_dest_iface_addr);
          next_addr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_next_iface_addr);
          i_addr    = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_iface_addr);

          Ipv6UpdateForwardingTable
          (node,
           dest_addr->interfaceAddr.ipv6,
           data->R_prefix_length,
           next_addr->interfaceAddr.ipv6,
           Ipv6GetInterfaceIndexFromAddress
           (node,
            &i_addr->interfaceAddr.ipv6),
           NETWORK_UNREACHABLE,
           ROUTING_PROTOCOL_OLSRv2_NIIGATA);

          MEM_free(dest_addr);
          MEM_free(next_addr);
          MEM_free(i_addr);

          tmp = tmp->next;
      }
      }
  }
}

static void
RoutingOLSRv2_Niigata_FinalizeQualnetRoute(Node *node)
{
    struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
    olsrd_config* olsr_cnf = olsr->olsr_cnf;

    if(olsr_cnf->ip_version == AF_INET)
    {
    RoutingOLSRv2_Niigata_InitQualnetRoute(node);
    }
    else
    {
    NetworkDataIp *networkDataIp = node->networkData.networkVar;
    route_init(networkDataIp->ipv6);
    }
}

static void
RoutingOLSRv2_Niigata_PrintQualnetRoutingTable(Node *node)
{
    struct olsrv2* olsr = (struct olsrv2 *)node->appData.olsrv2;
    olsrd_config* olsr_cnf = olsr->olsr_cnf;



    if(olsr_cnf->ip_version == AF_INET)
    {
    NetworkPrintForwardingTable(node);
    }
    else if(olsr_cnf->ip_version == AF_INET6)
    {
    Ipv6PrintForwardingTable(node);
    }
    else
    {
    olsr_error("%s: (%d) Un known ip_version.", __func__, __LINE__);
    }
}

static void
RoutingOLSRv2_Niigata_QualnetRoute(Node *node)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;
  olsrd_config* olsr_cnf = olsr->olsr_cnf;

  Address* dest_addr = NULL;
  Address* next_addr = NULL;
  Address* i_addr = NULL;


  OLSR_LIST_ENTRY *tmp = NULL;
  OLSR_ROUTING_TUPLE *data = NULL;
  int hash_index;

   RoutingOLSRv2_Niigata_InitQualnetRoute(node);

  if(olsr_cnf->ip_version == AF_INET6)
  {
      for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
      {
      OLSR_DeleteList_Static(&olsr->routing_set_old[hash_index].list);
      OLSR_InitList(&olsr->routing_set_old[hash_index].list);
      OLSR_CopyList(&olsr->routing_set_old[hash_index].list, &olsr->routing_set[hash_index].list);
      }
  }

  for(hash_index = 0; hash_index < HASHSIZE; hash_index++)
  {
      tmp = olsr->routing_set[hash_index].list.head;
      while(tmp)
      {
      data = (OLSR_ROUTING_TUPLE *)tmp->data;

      dest_addr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_dest_iface_addr);
      next_addr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_next_iface_addr);
      i_addr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, data->R_iface_addr);

      NodeAddress mask = 0;

      if(data->R_prefix_length == 32)
      {
          mask = 0xffffffff;
      }
      else if(data->R_prefix_length == 24)
      {
          mask = 0xffffff00;
      }
      else if(data->R_prefix_length == 16)
      {
          mask = 0xffff0000;
      }
      else if(data->R_prefix_length == 8)
      {
          mask = 0xff000000;
      }
      else if(data->R_prefix_length == 0)
      {
          mask = 0x00000000;
      }
      else
      {
          for(int i=0; i<data->R_prefix_length; i++)
          {
          mask += 1 << (31 - i);
          }
      }

      if(olsr_cnf->ip_version == AF_INET)
      {
          NetworkUpdateForwardingTable
          (node,
           dest_addr->interfaceAddr.ipv4,
           mask,
           next_addr->interfaceAddr.ipv4,
           NetworkIpGetInterfaceIndexFromAddress(node,i_addr->interfaceAddr.ipv4),
           data->R_dist,
           ROUTING_PROTOCOL_OLSRv2_NIIGATA);
      }
      else if(olsr_cnf->ip_version == AF_INET6)
      {

          Ipv6UpdateForwardingTable
          (node,
           dest_addr->interfaceAddr.ipv6,
           data->R_prefix_length,
           next_addr->interfaceAddr.ipv6,
           Ipv6GetInterfaceIndexFromAddress
           (node,
            &i_addr->interfaceAddr.ipv6),
           data->R_dist,
           ROUTING_PROTOCOL_OLSRv2_NIIGATA);
      }
      else
      {
          olsr_error("%s: (%d) Un known ip_version.", __func__, __LINE__);
      }

      MEM_free(dest_addr);
      MEM_free(next_addr);
      MEM_free(i_addr);

      tmp = tmp->next;
      }
  }

  if(DEBUG_OLSRV2)
  {
     //Commented to avoid printing forwarding tables on screen
     //RoutingOLSRv2_Niigata_PrintQualnetRoutingTable(node);
  }
}

static void
RoutingOLSRv2_Niigata_CheckTimeoutTuples(Node *node)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  Message    *timeoutTuplesMsg = NULL;

  olsr_check_timeout_tuples(olsr);

  olsr_process_changes(olsr);

  if(olsr->changes_neighborhood || olsr->changes_topology)
  {
      RoutingOLSRv2_Niigata_QualnetRoute(node);
  }

  //flush changes flags
  olsr->changes_neighborhood = OLSR_FALSE;
  olsr->changes_topology = OLSR_FALSE;


  //set next event
  timeoutTuplesMsg = MESSAGE_Alloc(node,
                   APP_LAYER,
                   APP_ROUTING_MPOLSRv2_NIIGATA,
                   MSG_APP_OLSRv2_NIIGATA_TimeoutTuples);


  MESSAGE_Send(node, timeoutTuplesMsg, (clocktype) olsr->qual_cnf->timeout_interval);
}


static void
RoutingOLSRv2_Niigata_UpdateCurrentSimTime(Node *node)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  olsr->current_sim_time = getSimTime(node);
}

static void
RoutingOLSRv2_Niigata_HandlePacket(Node *node, Message *msg)
{

  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  //NON-OLSRv2 node received OLSRv2 packet
  if (olsr == NULL)
  {
	//for the compatiblity of mpolsr and olsr, possiblly an olsr packet
//	olsr = (struct olsrv2 *)node->appData.olsrv2;
	//other packet
//	if(olsr == NULL )
	  return;
  }

  olsr_u8_t *packet = NULL;
  olsr_u16_t packet_size;
  UdpToAppRecv *udpToApp = NULL;
  union olsr_ip_addr *source_addr = NULL;
  union olsr_ip_addr saddr;
  int incomingInterface;

  olsrd_config* olsr_cnf = olsr->olsr_cnf;

  packet = (olsr_u8_t *) MESSAGE_ReturnPacket(msg);
  packet_size = (olsr_u16_t) MESSAGE_ReturnPacketSize(msg);

  udpToApp = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);

  incomingInterface = udpToApp->incomingInterfaceIndex;

  NetworkType networkType;

  if (olsr_cnf->ip_version == AF_INET) {
     networkType = NETWORK_IPV4;
  }
  else
  {
     networkType = NETWORK_IPV6;
  }

  if ((NetworkIpGetUnicastRoutingProtocolType(node,incomingInterface,networkType)
      != ROUTING_PROTOCOL_OLSRv2_NIIGATA)&&(NetworkIpGetUnicastRoutingProtocolType(node,incomingInterface,networkType)
      != ROUTING_PROTOCOL_MPOLSRv2_NIIGATA))
  {
      return;
  }

  source_addr =
    RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, udpToApp->sourceAddr);
  memcpy(&saddr, source_addr, sizeof(union olsr_ip_addr));

   //now parse packet
  olsr->parsingIfNum = olsr->interfaceMappingQualnet[incomingInterface];

  assert(olsr->parsingIfNum != OLSR_INVALID_INTERFACE);

  if(DEBUG_OLSRV2)
  {
      char* paddr =
      olsr_niigata_ip_to_string(olsr, &olsr->iface_addr[olsr->parsingIfNum]);
      olsr_printf("Receiving node iface_addr = %s\n", paddr);
      free(paddr);
      paddr = olsr_niigata_ip_to_string(olsr, source_addr);
      olsr_printf("Receiving Message source_addr = %s\n", paddr);
      free(paddr);

      RoutingOLSRv2_Niigata_DumpPacket((char *)packet,packet_size);
  }

  olsr->stat.recvMsgSize += packet_size;
  if(DEBUG_OLSRV2)
  {
      olsr_printf("\nIncrement Received Msg Size to %lld.\n",olsr->stat.recvMsgSize);
  }
  RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);
  parse_packet(olsr,
           (char *)packet,
           packet_size,
           &olsr->iface_addr[olsr->parsingIfNum],
           saddr);

  olsr_process_changes(olsr);

  if(olsr->changes_neighborhood || olsr->changes_topology)
  {
      RoutingOLSRv2_Niigata_QualnetRoute(node);
  }

  //flush changes flags
  olsr->changes_neighborhood = OLSR_FALSE;
  olsr->changes_topology = OLSR_FALSE;

  int iface_num;
  for(iface_num=0; iface_num < olsr->iface_num; iface_num++)
  {
      if(olsr->forwardMsg[iface_num] == NULL &&
     check_forward_infomation(olsr, (unsigned char)iface_num))
      {
      Message *timeoutForwardMsg;

      clocktype delay =
          (clocktype) (RANDOM_nrand(olsr->seed) % olsr->qual_cnf->max_forward_jitter);

      timeoutForwardMsg = MESSAGE_Alloc(node,
                        APP_LAYER,
                        APP_ROUTING_MPOLSRv2_NIIGATA,
                        MSG_APP_OLSRv2_NIIGATA_TimeoutForward);

      MESSAGE_InfoAlloc(node, timeoutForwardMsg, sizeof(unsigned char));
      *(unsigned char* )MESSAGE_ReturnInfo(timeoutForwardMsg) = olsr->interfaceMappingOlsr[iface_num];
      olsr->forwardMsg[iface_num] = (void* )timeoutForwardMsg;

      MESSAGE_Send(node, timeoutForwardMsg, delay);
      }
  }

  MEM_free(source_addr);
}

static void RoutingOLSRv2_Niigata_SendOutPacket(Node* node,Message* msg){
	NodeAddress nextHop;
	nextHop = 0xc0000002;
	NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,nextHop);
}

//set source route for new packets
int OLSRSetSourceRoute(
	Node * node,
	Message * msg,
	m_rtable_t::iterator rt_it,
	NodeAddress destAddr,
	bool routeRecoveryFlag){


	unsigned char *dataPtr;
    int dataLen;
    unsigned short payloadLen;
    NodeAddress nextHop;

	olsr_u8_t version = 4;
    olsr_u8_t protocol = 0;
	olsr_u16_t numNodesInSrcRt = 0;
	olsr_u16_t reserve = 0;
	olsr_u16_t flow = 0;

    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    int ipHeaderSize = IpHeaderSize(ipHeader);
    IpHeaderType origIpHeader;

    NetworkDataIp* ipNetworkData = (NetworkDataIp *) node->networkData.networkVar;

    // Back up original IP header
    memcpy(&origIpHeader, ipHeader, ipHeaderSize);

    // Remove IP header
    MESSAGE_RemoveHeader(node, msg, ipHeaderSize, TRACE_IP);

	//rt_it++;
/*	if(DEBUG_OLSRV2){
		
			printf("\n");
			for (int i = 0;i<MAX_SR_LEN; i++){
				NodeAddress add_t = (*(rt_it->second->addr_[i])).v4;
				printf("%x \t" ,add_t);
					if (add_t == destAddr){
						break;
					}
			}
	}*/

	//if it's route recovery, we need to remove the old source route head
	if(routeRecoveryFlag){
			dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);

		//move the pointer to the NoOfNodes field
		dataPtr += 2*sizeof(olsr_u16_t);

		olsr_u16_t* tempNoOfNodes = (olsr_u16_t*)dataPtr;
		

		MESSAGE_ShrinkPacket(node, msg, SIZE_OF_MULTIPATH_COMMON_HEAD + *tempNoOfNodes * sizeof(NodeAddress));

	}

	//get number of hops
	for(;;){
		
		NodeAddress add_t = (*(rt_it->second->addr_[numNodesInSrcRt])).v4;
		numNodesInSrcRt ++;
		if (add_t == destAddr){
			break;
		}
	}

	dataLen = payloadLen = SIZE_OF_MULTIPATH_COMMON_HEAD + numNodesInSrcRt * sizeof(NodeAddress);

	MESSAGE_ExpandPacket(node, msg, dataLen);

    dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);

	//set commen header for the multipath
	*dataPtr = version;
	dataPtr++;
	
	*dataPtr = protocol;
	dataPtr++;

	memcpy(dataPtr, &reserve, sizeof(olsr_u16_t));
	dataPtr += sizeof(olsr_u16_t);

	memcpy(dataPtr, &numNodesInSrcRt, sizeof(olsr_u16_t));
	dataPtr += sizeof(olsr_u16_t);

	memcpy(dataPtr, &flow, sizeof(olsr_u16_t));
	dataPtr += sizeof(olsr_u16_t);

	//set the source route
	for(int i = 0; i<numNodesInSrcRt; i++){
		NodeAddress add_t = (*(rt_it->second->addr_[i])).v4;
		memcpy(dataPtr, &add_t, sizeof(NodeAddress));
		dataPtr += sizeof(NodeAddress);
	}

	if (DEBUG_OLSRV2){
		dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);
		olsr_u8_t* tempVersion = (olsr_u8_t*)dataPtr;
		dataPtr ++;

		olsr_u8_t* tempProtocol = (olsr_u8_t*)dataPtr;
		dataPtr ++;
		
		olsr_u16_t* tempReserve = (olsr_u16_t*)dataPtr;
		dataPtr += sizeof(olsr_u16_t);

		olsr_u16_t* tempNoOfNodes = (olsr_u16_t*)dataPtr;
		dataPtr += sizeof(olsr_u16_t);

		olsr_u16_t* tempFlow = (olsr_u16_t*)dataPtr;
		dataPtr += sizeof(olsr_u16_t);
/*		
		printf("\n--------the source route info-----------\n");
		printf("version:  %d \t Protocol: %d \t Reseve: %d \n", 
			*tempVersion, *tempProtocol, *tempReserve);
		printf("No. of hops: %d \t Flow: %d\n", *tempNoOfNodes, *tempFlow);

		printf("hops:\t");
		
		for(int i = 0; i< numNodesInSrcRt; i++){
			NodeAddress* tempAddr = (NodeAddress*)dataPtr;
			printf("%x --->",*tempAddr);
			dataPtr += sizeof(NodeAddress);
		}
		printf("\n----------------------------\n");
		*/
		
	}

	MESSAGE_AddHeader(node, msg, ipHeaderSize, TRACE_IP);

	// Change different fields of ip header
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    memcpy(ipHeader, &origIpHeader, ipHeaderSize);
    //IpHeaderSetIpDontFrag(&(ipHeader->ipFragment), 1);
    IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),MESSAGE_ReturnPacketSize(msg));
	//ipHeader->ip_ttl = (unsigned char) rtPtr->hopCount;
    //ipHeader->ip_p = IPPROTO_DSR;

	return numNodesInSrcRt;
	
	

}

//std::vector<NodeAddress>* 
//get source route before the current node
void OLSRGetSourceRoute (Node* node, Message* msg,std::vector<NodeAddress>* sourceRoute){
	unsigned char *dataPtr;
    int dataLen;
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
//	std::vector<NodeAddress> sourceRoute;

	IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
//	NodeAddress dest = ipHeader->ip_dst;
//	NodeAddress olsrDest = GetOLSRFromQualnetIPv4(node,dest);

	NodeAddress current = NetworkIpGetInterfaceAddress(node,DEFAULT_INTERFACE);
	NodeAddress olsrCurrent = GetOLSRFromQualnetIPv4(node,current);
    int ipHeaderSize = IpHeaderSize(ipHeader);

	dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);

	dataPtr += ipHeaderSize + SIZE_OF_MULTIPATH_COMMON_HEAD ;

	NodeAddress* tempAddr = (NodeAddress*)dataPtr;

	for(;;){
		(*sourceRoute).push_back(*tempAddr);
//		printf("%x\t",*tempAddr);
		if(*tempAddr == olsrCurrent)
			break;
		dataPtr += sizeof(NodeAddress);
		tempAddr = (NodeAddress*)dataPtr;
	}
//	printf("*****************\n");
	
	//return sourceRoute;
}

NodeAddress OLSRGetNextHopFromSR(Node * node,Message * msg,NodeAddress srcAddr,NodeAddress destAddr){

	unsigned char *dataPtr;
    int dataLen;
    unsigned short payloadLen;
    NodeAddress* nextHop;
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;


    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
//	NodeAddress srcAddr = ipHeader->ip_src;

    int ipHeaderSize = IpHeaderSize(ipHeader);

	dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);

	dataPtr += ipHeaderSize + SIZE_OF_MULTIPATH_COMMON_HEAD ;

	NodeAddress* tempAddr = (NodeAddress*)dataPtr;

	Address* tempQualAddr;
//	(*tempQualAddr).networkType = NETWORK_IPV4;

	olsr_ip_addr tempOlsraddr;
	tempOlsraddr.v4 = srcAddr;	

	//if the node is the originator of the packet
	tempQualAddr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr, tempOlsraddr);
/*	if(NetworkIpIsMyIP(node, (*tempQualAddr).interfaceAddr.ipv4)){
		nextHop = tempAddr;//(NodeAddress*)dataPtr;
	//	printf("*********next hop: %x**********\n", *nextHop);
		return *nextHop;
	}*/

//	tempQualAddr = 
	

	do {
		tempOlsraddr.v4 = *tempAddr;
		tempQualAddr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr,tempOlsraddr);
		dataPtr += sizeof(NodeAddress);
		tempAddr = (NodeAddress*)dataPtr;

	//	printf("*********** %x, %x**********\n",NetworkIpGetInterfaceAddress(node,DEFAULT_INTERFACE),*tempAddr);
	} while (!NetworkIpIsMyIP(node, (*tempQualAddr).interfaceAddr.ipv4));

	nextHop = (NodeAddress*)dataPtr;

	return *nextHop;
}

NodeAddress GetQualnetIPv4FromOLSR(Node* node,NodeAddress olsraddr){
/*	Address qualnetDest, qualnetSrc;
	qualnetDest.networkType = qualnetSrc.networkType = NETWORK_IPV4;
	qualnetDest.interfaceAddr.ipv4 = destAddr;
	qualnetSrc.interfaceAddr.ipv4 = srcAddr;
	
	olsr_ip_addr *olsrDest, *olsrSrc;
	olsrDest = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetDest);
	olsrSrc = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetSrc);
*/

	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
	Address* qualaddr;
//	qualaddr.networkType = NETWORK_IPV4;

	olsr_ip_addr olsripaddr;
	olsripaddr.v4 = olsraddr;
	qualaddr = RoutingOLSRv2_Niigata_GetQualnetAddress(olsr,olsripaddr);
	return (*qualaddr).interfaceAddr.ipv4;
	
}

NodeAddress GetOLSRFromQualnetIPv4(Node* node, NodeAddress qualnetaddr){
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;

	Address qualaddr;
	qualaddr.networkType = NETWORK_IPV4;
	qualaddr.interfaceAddr.ipv4 = qualnetaddr;
	
	olsr_ip_addr* olsripaddr;
	olsripaddr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualaddr);

	return (*olsripaddr).v4;
}

float OLSRCostFunctionFp(Node* node, float value){
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
    //olsrd_config* olsr_cnf = olsr->olsr_cnf;
    olsrv2_qualnet_config* olsr_cnf = olsr->qual_cnf;

//	olsr_cnf->hello_interval = 5;
//	olsr_cnf->fec = TRUE;
	value = olsr_cnf->cost_fp_a * value + olsr_cnf->cost_fp_b;
	return value;
}

float OLSRCostFunctionFe(Node* node, float value){
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
    //olsrd_config* olsr_cnf = olsr->olsr_cnf;
    olsrv2_qualnet_config* olsr_cnf = olsr->qual_cnf;

	value = olsr_cnf->cost_fe_a * value + olsr_cnf->cost_fe_b;
	return value;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueBytesInQueue()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              how many packets are in a queue.  There may be multiple
//              queues on an interface, so the priority of the desired
//              queue is also provided.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              BOOL specificPriorityOnly
//                  Should we only get the number of packets in queue for
//                  the specified priority only or for all priorities.
//              QueuePriorityType priority
//                  Priority of queue.
// RETURN       Number of bytes in queue.
//-----------------------------------------------------------------------------

int
NetworkIpOutputQueueBytesInQueue(
    Node *node,
    int interfaceIndex,
    BOOL specificPriorityOnly,
    QueuePriorityType priority)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler = NULL;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;
    return (*scheduler).bytesInQueue(priority);
}





void
RoutingOLSRv2_Niigata_LinkLayerNotificationHandler
(Node *node,
 const Message *msg,
 const NodeAddress nextHopAddress,
 const int interfaceIndex)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;
  olsrd_config* olsr_cnf = olsr->olsr_cnf;

  char* paddr;

  Address qualnet_addr;
  memset(&qualnet_addr, 0, sizeof(Address));

  if(DEBUG_OLSRV2)
  {
      olsr_printf("%s: Link Layer Notification!!\n", __FUNCTION__);
  }

  if(olsr_cnf->ip_version == AF_INET)
  {
      qualnet_addr.networkType = NETWORK_IPV4;
      qualnet_addr.interfaceAddr.ipv4 = nextHopAddress;
  }
  else
  {
      olsr_error("Does not support IPv6\n");
  }

  if(DEBUG_OLSRV2)
  {
      union olsr_ip_addr* next_addr =
      RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, qualnet_addr);
      paddr = olsr_niigata_ip_to_string(olsr, next_addr);
      olsr_printf("Link Break is IP(%s)\n",paddr);
      MEM_free(paddr);
      MEM_free(next_addr);
  }


  RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);

  union olsr_ip_addr* addr1 = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, qualnet_addr);
  union olsr_ip_addr  saddr1;

  memcpy(&saddr1, addr1, sizeof(union olsr_ip_addr));
/*
    if(DEBUG_OLSRV2)
  {
     //Commented to avoid printing forwarding tables on screen
      // RoutingOLSRv2_Niigata_PrintQualnetRoutingTable(node);
      			OLSR_LIST_ENTRY *tmp_A = NULL;
			tmp_A = olsr->link_set.head;
			OLSR_LINK_TUPLE *link_data = NULL;
			printf("\n***********%d---->%x, link info***********\n",node->nodeId,saddr1.v4);

  			while(tmp_A){
      			link_data = (OLSR_LINK_TUPLE *)tmp_A->data;

				printf("%x\t",link_data->L_neighbor_iface_addr.v4);
				tmp_A = tmp_A->next;
			}
			printf("\n*****************************\n");
  }*/

  proc_link_layer_notification(olsr, saddr1);

  //need to delete the corresponding link set
   	OLSR_LIST_ENTRY *tmp_A = NULL;
	tmp_A = olsr->link_set.head;
	OLSR_LINK_TUPLE *link_data = NULL;
	while(tmp_A){
		link_data = (OLSR_LINK_TUPLE *)tmp_A->data;
		if(link_data->L_neighbor_iface_addr.v4 == saddr1.v4){
			OLSR_DeleteListEntry(&olsr->link_set,tmp_A);
			break;
		}
		tmp_A = tmp_A->next;
	}
/*
    if(DEBUG_OLSRV2){
     //Commented to avoid printing forwarding tables on screen
      // RoutingOLSRv2_Niigata_PrintQualnetRoutingTable(node);
      			OLSR_LIST_ENTRY *tmp_A = NULL;
			tmp_A = olsr->link_set.head;
			OLSR_LINK_TUPLE *link_data = NULL;
			printf("\n***********%d---->%x, link info***********\n",node->nodeId,saddr1.v4);

  			while(tmp_A){
      			link_data = (OLSR_LINK_TUPLE *)tmp_A->data;

				printf("%x\t",link_data->L_neighbor_iface_addr.v4);
				tmp_A = tmp_A->next;
			}
			printf("\n*****************************\n");
  	}*/
  
  if(DEBUG_OLSRV2)
  {
      print_mpr_set(olsr);
 //     print_routing_set(olsr);
  }

 /* if(olsr->changes_neighborhood || olsr->changes_topology)
  {
      RoutingOLSRv2_Niigata_QualnetRoute(node);
  }*/
  //flush changes flags
  olsr->changes_neighborhood = OLSR_FALSE;
  olsr->changes_topology = OLSR_FALSE;

  if(olsr->qual_cnf->packet_restoration)
  {
      IpHeaderType* ipHeader;
      Address address;
      union olsr_ip_addr* source_addr;
      union olsr_ip_addr* dest_addr;
/*
      if(DEBUG_OLSRV2)
      {
      olsr_printf("%s: Packet Restration!!\n", __FUNCTION__);
      }
      ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
      address.networkType = NETWORK_IPV4;
      address.interfaceAddr.ipv4 = ipHeader->ip_src;
      source_addr =
      RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);

      address.interfaceAddr.ipv4 = ipHeader->ip_dst;
      dest_addr =
      RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);

      if(DEBUG_OLSRV2)
      {
      paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
      olsr_printf("main_addr = %s\n", paddr);
      MEM_free(paddr);
      paddr = olsr_niigata_ip_to_string(olsr, source_addr);
      olsr_printf("source_addr = %s\n", paddr);
      MEM_free(paddr);
      paddr = olsr_niigata_ip_to_string(olsr, dest_addr);
      olsr_printf("dest_addr = %s\n", paddr);
      MEM_free(paddr);
      }

      switch(olsr->qual_cnf->restoration_type)
      {
      case 1: //Simple
      {
          Message *restMsg = MESSAGE_Duplicate(node, msg);

          if(DEBUG_OLSRV2)
          {
          olsr_printf("%s: Simple Restration!!\n", __FUNCTION__);
          }

          RouteThePacketUsingLookupTable(node, restMsg, interfaceIndex);
          break;
      }

      case 2: //Full
      {
          ERROR_Assert(OLSR_FALSE, "Not Support Full Restration...");
          break;
      }

      default:
      {
          ERROR_Assert(OLSR_FALSE, "No Such Restration Type...");
          break;
      }
      }

      MEM_free(source_addr);
      MEM_free(dest_addr);*/
  }

  MEM_free(addr1);
}


static void
OLSRv2InitConfigParameters(Node* node, const NodeInput* nodeInput, int interfaceIndex)
{
    BOOL wasFound;
    char buf[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];

    struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
    olsrd_config* olsr_cnf = olsr->olsr_cnf;

    OLSRv2QualConf *qual_cnf =
      (OLSRv2QualConf *)MEM_malloc(sizeof(OLSRv2QualConf));
    memset(qual_cnf,0,sizeof(OLSRv2QualConf));

    olsr->qual_cnf = qual_cnf;


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-HELLO-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->hello_interval);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-HELLO-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->hello_interval);
    }

    if (!wasFound)
    {
 /*       sprintf(errStr, "Hello Interval Parameter not specified"
                        " for Node %d, hence continuing with the"
                        " default value: %dS. \n",
                        node->nodeId, (int)(OLSRv2_DEFAULT_HELLO_INTERVAL / SECOND) );
        ERROR_ReportWarning(errStr);*/

        qual_cnf->hello_interval = OLSRv2_DEFAULT_HELLO_INTERVAL;
    }
    else
    {
        if (qual_cnf->hello_interval <= 0 )
        {
           sprintf(errStr, "Invalid Hello Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId, (int)(OLSRv2_DEFAULT_HELLO_INTERVAL / SECOND) );
            ERROR_ReportWarning(errStr);

            qual_cnf->hello_interval = OLSRv2_DEFAULT_HELLO_INTERVAL;
        }
    }

    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-TC-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->tc_interval);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-TC-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->tc_interval);
    }

    if (!wasFound)
    {
  /*      sprintf(errStr, "TC Interval Parameter not specified"
                        " for Node %d, hence continuing with the"
                        " default value: %dS. \n",
                        node->nodeId, (int)(OLSRv2_DEFAULT_TC_INTERVAL / SECOND));
        ERROR_ReportWarning(errStr);*/
        qual_cnf->tc_interval = OLSRv2_DEFAULT_TC_INTERVAL;
    }
    else
    {
        if (qual_cnf->tc_interval <= 0 )
        {
            sprintf(errStr, "Invalid TC Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId, (int)(OLSRv2_DEFAULT_TC_INTERVAL / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->tc_interval = OLSRv2_DEFAULT_TC_INTERVAL;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-REFRESH-TIMEOUT-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->timeout_interval);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-REFRESH-TIMEOUT-INTERVAL",
            &wasFound,
            (clocktype *)&qual_cnf->timeout_interval);
    }

    if (!wasFound)
    {
  /*      sprintf(errStr, "Timeout Interval Parameter not specified"
                " for Node %d, hence continuing with the"
                " default value: %dS. \n",
                node->nodeId, (int)(OLSRv2_DEFAULT_REFRESH_TIMEOUT_INTERVAL / SECOND));
        ERROR_ReportWarning(errStr);*/

        qual_cnf->timeout_interval = OLSRv2_DEFAULT_REFRESH_TIMEOUT_INTERVAL;
    }
    else
    {
        if (qual_cnf->timeout_interval <= 0 )
        {
            sprintf(errStr, "Invalid Timeout Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId,
                            (int)(OLSRv2_DEFAULT_REFRESH_TIMEOUT_INTERVAL / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->timeout_interval = OLSRv2_DEFAULT_REFRESH_TIMEOUT_INTERVAL;
        }
    }


    //setting Hello jitter
    qual_cnf->max_hello_jitter = OLSRv2_DEFAULT_MAX_HELLO_JITTER;

    //setting TC jitter
    qual_cnf->max_tc_jitter = OLSRv2_DEFAULT_MAX_TC_JITTER;

    //setting Forward jitter
    qual_cnf->max_forward_jitter = OLSRv2_DEFAULT_MAX_FORWARD_JITTER;


    if (olsr_cnf->ip_version == AF_INET)
    {
        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-START-HELLO",
            &wasFound,
            (clocktype *)&qual_cnf->start_hello);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-START-HELLO",
            &wasFound,
            (clocktype *)&qual_cnf->start_hello);
    }

    if (!wasFound)
    {
  /*      sprintf(errStr, "Start Hello Interval Parameter not specified"
                " for Node %d, hence continuing with the"
                " default value: %dS. \n",
                node->nodeId, (int)(OLSRv2_DEFAULT_START_HELLO / SECOND));
        ERROR_ReportWarning(errStr);*/

        qual_cnf->start_hello = OLSRv2_DEFAULT_START_HELLO;
    }
    else
    {
        if (qual_cnf->start_hello <= 0 )
        {
            sprintf(errStr, "Invalid Start Hello Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId, (int)(OLSRv2_DEFAULT_START_HELLO / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->start_hello = OLSRv2_DEFAULT_START_HELLO;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-START-TC",
            &wasFound,
            (clocktype *)&qual_cnf->start_tc);
    }

    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

         IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-START-TC",
            &wasFound,
            (clocktype *)&qual_cnf->start_tc);
    }

    if (!wasFound)
    {
   /*     sprintf(errStr, "Start TC Interval Parameter not specified"
                " for Node %d, hence continuing with the"
                " default value: %dS. \n",
                node->nodeId, (int)(OLSRv2_DEFAULT_START_TC / SECOND));
        ERROR_ReportWarning(errStr);*/

        qual_cnf->start_tc = OLSRv2_DEFAULT_START_TC;
    }
    else
    {
        if (qual_cnf->start_tc <= 0 )
        {
            sprintf(errStr, "Invalid Start TC Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId, (int)(OLSRv2_DEFAULT_START_TC / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->start_tc = OLSRv2_DEFAULT_START_TC;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-START-REFRESH-TIMEOUT",
            &wasFound,
            (clocktype *)&qual_cnf->start_timeout);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-START-REFRESH-TIMEOUT",
            &wasFound,
            (clocktype *)&qual_cnf->start_timeout);
    }

    if (!wasFound)
    {
  /*      sprintf(errStr, "Start Timeout Interval Parameter not specified"
                " for Node %d, hence continuing with the"
                " default value: %dS. \n",
                node->nodeId, (int)(OLSRv2_DEFAULT_START_REFRESH_TIMEOUT / SECOND));
        ERROR_ReportWarning(errStr);*/

        qual_cnf->start_timeout = OLSRv2_DEFAULT_START_REFRESH_TIMEOUT;
    }
    else
    {
        if (qual_cnf->start_timeout <= 0 )
        {
            sprintf(errStr, "Invalid Start Timeout Interval Parameter specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId,
                            (int)(OLSRv2_DEFAULT_START_REFRESH_TIMEOUT / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->start_timeout = OLSRv2_DEFAULT_START_REFRESH_TIMEOUT;
        }
    }

    wasFound = FALSE;

    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-NEIGHBOR-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->neighbor_hold_time);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-NEIGHBOR-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->neighbor_hold_time);
    }

    if (!wasFound)
    {
        qual_cnf->neighbor_hold_time =
                                  OLSRv2_DEFAULT_NEIGHBOR_HOLD_TIME / SECOND;
    }
    else
    {

        qual_cnf->neighbor_hold_time = qual_cnf->neighbor_hold_time / SECOND;

        if (qual_cnf->neighbor_hold_time <= 0 )
        {
           sprintf(errStr, "Invalid Neighbor Hold Time specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId,
                            (int)(OLSRv2_DEFAULT_NEIGHBOR_HOLD_TIME / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->neighbor_hold_time =
                                  OLSRv2_DEFAULT_NEIGHBOR_HOLD_TIME / SECOND;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-TOPOLOGY-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->topology_hold_time);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-TOPOLOGY-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->topology_hold_time);
    }

    if (!wasFound)
    {
        qual_cnf->topology_hold_time =
                                  OLSRv2_DEFAULT_TOPOLOGY_HOLD_TIME / SECOND;
    }
    else
    {

        qual_cnf->topology_hold_time = qual_cnf->topology_hold_time / SECOND;

        if (qual_cnf->topology_hold_time <= 0 )
        {
           sprintf(errStr, "Invalid Topology Hold Time specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId,
                            (int)(OLSRv2_DEFAULT_TOPOLOGY_HOLD_TIME / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->topology_hold_time =
                                  OLSRv2_DEFAULT_TOPOLOGY_HOLD_TIME / SECOND;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadTime(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-DUPLICATE-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->duplicate_hold_time);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadTime(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-DUPLICATE-HOLD-TIME",
            &wasFound,
            (clocktype *)&qual_cnf->duplicate_hold_time);
    }

    if (!wasFound)
    {
        qual_cnf->duplicate_hold_time =
                                 OLSRv2_DEFAULT_DUPLICATE_HOLD_TIME / SECOND;
    }
    else
    {
        qual_cnf->duplicate_hold_time = qual_cnf->duplicate_hold_time /SECOND;

        if (qual_cnf->duplicate_hold_time <= 0 )
        {
           sprintf(errStr, "Invalid Duplicate Hold Time specified"
                            " for Node %d, hence continuing"
                            " with the default value: %dS. \n",
                            node->nodeId,
                            (int)(OLSRv2_DEFAULT_DUPLICATE_HOLD_TIME / SECOND));
            ERROR_ReportWarning(errStr);

            qual_cnf->duplicate_hold_time =
                                 OLSRv2_DEFAULT_DUPLICATE_HOLD_TIME / SECOND;
        }
    }


    if (olsr_cnf->ip_version == AF_INET)
    {
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-LINK-LAYER-NOTIFICATION",
            &wasFound,
            buf);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadString(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-LINK-LAYER-NOTIFICATION",
            &wasFound,
            buf);
    }

    if(wasFound == TRUE)
      {
    if (strcmp(buf, "NO") == 0)
      {
        qual_cnf->link_layer_notification = OLSR_FALSE;
      }
    else if (strcmp(buf, "YES") == 0)
      {
        qual_cnf->link_layer_notification = OLSR_TRUE;
      }
    else
      {
          //ERROR_ReportError("Needs YES/NO against OLSRv2-LINK-LAYER-NOTIFICATION");
          sprintf(errStr, "Invalid value for Link Layer Notification"
              " specified for Node %d. Value should be"
              " either YES or NO. Hence"
              " continuing with the default value NO. \n",
              node->nodeId);
          ERROR_ReportWarning(errStr);

          qual_cnf->link_layer_notification =
                          (olsr_bool )OLSRv2_DEFAULT_LINK_LAYER_NOTIFICATION;
      }
      }
    else
      {
    qual_cnf->link_layer_notification =
      (olsr_bool )OLSRv2_DEFAULT_LINK_LAYER_NOTIFICATION;
      }


    if (olsr_cnf->ip_version == AF_INET)
    {
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-PACKET-RESTORATION",
            &wasFound,
            buf);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadString(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-PACKET-RESTORATION",
            &wasFound,
            buf);
    }

    if(wasFound == TRUE)
      {
    if (strcmp(buf, "NO") == 0)
      {
        qual_cnf->packet_restoration = OLSR_FALSE;
      }
    else if (strcmp(buf, "YES") == 0)
      {
        qual_cnf->packet_restoration = OLSR_TRUE;
      }
    else
      {
          //ERROR_ReportError("Needs YES/NO against OLSRv2-PACKET-RESTORATION");
          sprintf(errStr, "Invalid Packet Restoration Type"
              " specified for Node %d. Restoration type should be"
              " either YES or NO. Hence"
              " continuing with the default value. \n",
              node->nodeId);
          ERROR_ReportWarning(errStr);

          qual_cnf->packet_restoration =
                                (olsr_bool)OLSRv2_DEFAULT_PACKET_RESTORATION;
      }
      }
    else
      {
    qual_cnf->packet_restoration = (olsr_bool)OLSRv2_DEFAULT_PACKET_RESTORATION;
      }

    if(qual_cnf->packet_restoration == TRUE)
      {
    if (olsr_cnf->ip_version == AF_INET)
      {
        IO_ReadInt(
               node->nodeId,
               NetworkIpGetInterfaceAddress(node, interfaceIndex),
               nodeInput,
               "OLSRv2-RESTORATION-TYPE",
               &wasFound,
               &qual_cnf->restoration_type);
      }
    else
      {
        Address address;

        NetworkGetInterfaceInfo(
                    node,
                    interfaceIndex,
                    &address,
                    NETWORK_IPV6);

        IO_ReadInt(
               node->nodeId,
               &address.interfaceAddr.ipv6,
               nodeInput,
               "OLSRv2-RESTORATION-TYPE",
               &wasFound,
               &qual_cnf->restoration_type);
      }

    if (wasFound == FALSE)
      {
        qual_cnf->restoration_type = OLSRv2_DEFAULT_RESTORATION_TYPE;
      }
    else
      {
        if (qual_cnf->restoration_type != 1){
          sprintf(errStr, "Invalid Restoration Type"
              " specified for Node %d. Restoration type other"
              " than SIMPLE is not supported. Hence"
              " continuing with the default value %d. \n",
              node->nodeId, (int)OLSRv2_DEFAULT_RESTORATION_TYPE);
          ERROR_ReportWarning(errStr);

          qual_cnf->restoration_type = OLSRv2_DEFAULT_RESTORATION_TYPE;
        }
      }

      }

	if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadInt(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-NUMBER-OF-PATH",
            &wasFound,
            (int *)&qual_cnf->number_of_path);
		
    }
	if (!wasFound)
    {
        qual_cnf->number_of_path = OLSRv2_DEFAULT_NUMBER_OF_PATH;
    }

	if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadBool(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-ROUTE-RECOVERY",
            &wasFound,
            (int *)&qual_cnf->route_recovery);
		
    }
	if (!wasFound)
    {
        qual_cnf->route_recovery = (olsr_bool)OLSRv2_DEFAULT_ROUTE_RECOVERY;
    }

	if (olsr_cnf->ip_version == AF_INET)
    {

        IO_ReadBool(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-IP-SOURCE-ROUTING",
            &wasFound,
            (int *)&qual_cnf->ip_source_routing);
		
    }
	if (!wasFound)
    {
        qual_cnf->ip_source_routing = (olsr_bool)OLSRv2_DEFAULT_IP_SOURCE_ROUTING;
    }

	if (olsr_cnf->ip_version ==AF_INET){
		IO_ReadFloat(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-COST-Fp-A",
            &wasFound,
            (float *)&qual_cnf->cost_fp_a);
	}
	if (!wasFound){
		qual_cnf->cost_fp_a = OLSRv2_DEFAULT_COST_FpA;
	}

	
	if (olsr_cnf->ip_version ==AF_INET){
		IO_ReadFloat(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-COST-Fp-B",
            &wasFound,
            (float *)&qual_cnf->cost_fp_b);
	}
	if (!wasFound){
		qual_cnf->cost_fp_b = OLSRv2_DEFAULT_COST_FpB;
	}

	if (olsr_cnf->ip_version ==AF_INET){
		IO_ReadFloat(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-COST-Fe-A",
            &wasFound,
            (float *)&qual_cnf->cost_fe_a);
	}
	if (!wasFound){
		qual_cnf->cost_fe_a = OLSRv2_DEFAULT_COST_FeA;
	}

	if (olsr_cnf->ip_version ==AF_INET){
		IO_ReadFloat(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-COST-Fe-B",
            &wasFound,
            (float *)&qual_cnf->cost_fe_b);
	}
	if (!wasFound){
		qual_cnf->cost_fe_b = OLSRv2_DEFAULT_COST_FeB;
	}
}
  
static void
OLSRv2InitAttachedNetwork(Node* node,
                          const NodeInput* nodeInput,
                          int interfaceIndex)
{
    BOOL wasFound = FALSE;
    char buf[MAX_STRING_LENGTH];
    char* token = NULL;
    char errStr[MAX_STRING_LENGTH];
    char* next = NULL;
    char delims[] = {" \t"};
    char iotoken[MAX_STRING_LENGTH];
    struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
    olsrd_config* olsr_cnf = olsr->olsr_cnf;
    NodeAddress nodeId = node->nodeId;
    ATTACHED_NETWORK *attachedNetwork, *iterator;
    BOOL duplicateFound = FALSE;

    //olsr->attached_net_addr = NULL;
    //olsr->advNetAddrNum = 0;

    if (olsr_cnf->ip_version == AF_INET)
    {
        IO_ReadString(
            nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "OLSRv2-ATTACHED-NETWORK",
            &wasFound,
            buf);
    }
    else
    {
        Address address;

        NetworkGetInterfaceInfo(
            node,
            interfaceIndex,
            &address,
            NETWORK_IPV6);

        IO_ReadString(
            node->nodeId,
            &address.interfaceAddr.ipv6,
            nodeInput,
            "OLSRv2-ATTACHED-NETWORK",
            &wasFound,
            buf);
    }

    if (wasFound)
    {
        token = IO_GetDelimitedToken(iotoken, buf, delims, &next);
        if (token != NULL)
        {
            olsr->I_am_MPR_flag = OLSR_TRUE;
            while(token != NULL)
            {
                attachedNetwork =
                    (ATTACHED_NETWORK* )MEM_malloc(sizeof(ATTACHED_NETWORK));
                memset(attachedNetwork, 0, sizeof(ATTACHED_NETWORK));

                GetIpAddr(olsr, &attachedNetwork->network_addr, token);

                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
                if(token == NULL)
                {
                    sprintf(errStr, "Invalid Attached Network Configuration."
                                    " Configuration requires pair of"
                                    " Network Address and"
                                    " Network Prefix length.");
                    ERROR_Assert(OLSR_FALSE, errStr);
                    //assert(OLSR_FALSE);
                }
                attachedNetwork->prefix_length = (olsr_u8_t) atoi(token);

                iterator = olsr->attached_net_addr;
                while (iterator != NULL)
                {
                    if (equal_ip_addr((struct olsrv2 *)olsr,
                                        &iterator->network_addr,
                                        &attachedNetwork->network_addr))
                    {
                        duplicateFound = TRUE;
                        //duplicate entry found in configuration
                        //now checking for prefix length
                        if (attachedNetwork->prefix_length >
                                         iterator->prefix_length)
                        {
                            //updating prefix length
                            iterator->prefix_length =
                                             attachedNetwork->prefix_length;
                        }
                        break;
                    }
                    else
                    {
                        iterator = iterator->next;
                    }
                }//End of while (iterator !=NULL)

                if (!duplicateFound)
                {
                    attachedNetwork->next = olsr->attached_net_addr;
                    olsr->attached_net_addr = attachedNetwork;
                    olsr->advNetAddrNum++;
                }
                else
                {
                    free(attachedNetwork);
                    duplicateFound = FALSE;
                }

                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            }//End of while(token != NULL)
        }
    }
}


void
RoutingMPOLSRv2_Niigata_Init(Node *node,
                           const NodeInput* nodeInput,
                           int interfaceIndex,
                           NetworkType networkType)
{
  Message *timeoutMsg = NULL, *helloPeriodicMsg = NULL, *tcPeriodicMsg = NULL;

  char* paddr;

  struct olsrv2 *olsr =
    (struct olsrv2 *)MEM_malloc(sizeof(struct olsrv2));  //wiss: beta3ti espace vide bi 7ajm el olsrV2 bel memoire 
  memset(olsr, 0, sizeof(struct olsrv2));

  node->appData.olsrv2 = olsr;
  olsrd_config* olsr_cnf = NULL;


  if(DEBUG_OUTPUT || DEBUG_OLSRV2)
  {
      //init olsr debug
      init_olsr_debug();
      olsr_printf("************************************\n");
      olsr_printf("initiate node %3d\n", node->nodeId);
  }

  //init olsr config
  olsr_cnf = (struct olsrd_config *)MEM_malloc(sizeof(struct olsrd_config));
  memset(olsr_cnf, 0, sizeof(struct olsrd_config));

  olsr->olsr_cnf = olsr_cnf;

  RANDOM_SetSeed(olsr->seed,
                 node->globalSeed,
                 node->nodeId,
                 APP_ROUTING_MPOLSRv2_NIIGATA);

    if(networkType == NETWORK_IPV4){
      olsr_cnf->ip_version = AF_INET;
      olsr_cnf->ipsize = sizeof(olsr_u32_t);

      if(DEBUG_OUTPUT || DEBUG_OLSRV2)
      {
      olsr_printf("IP version = 4, ipsize = %d\n", (int)olsr_cnf->ipsize);
      }
    }
    else if(networkType == NETWORK_IPV6){
      olsr_cnf->ip_version = AF_INET6;
      olsr_cnf->ipsize = sizeof(struct in6_addr_qualnet);

      if(DEBUG_OUTPUT || DEBUG_OLSRV2)
      {
      olsr_printf("IP version = 6, ipsize = %d\n", (int)olsr_cnf->ipsize);
      }
  }
  else
  {
      olsr_error("Unknown IP type\n");
  }

  OLSRv2InitConfigParameters(node, nodeInput, interfaceIndex);

  //init olsr debug level parameter by 0
  olsr_cnf->debug_level = 0;
  //init tuples
  olsr_init_tuples(olsr);
  //init message seqno
  init_msg_seqno(olsr);
  //init packet seqno
  init_packet_seqno(olsr);
  //init parser
  olsr_init_parser(olsr);
  //init parse address
  init_parse_address(olsr);

  union olsr_ip_addr* m_addr = NULL;
  //init orignator address
  if(olsr_cnf->ip_version == AF_INET){
      Address address;
      address.networkType = NETWORK_IPV4;
      address.interfaceAddr.ipv4 =
      NetworkIpGetInterfaceAddress(node, interfaceIndex); //wiss: bta3tiya intindexs bta3tik ip address

      m_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);

      memcpy(&olsr->main_addr, m_addr, sizeof(union olsr_ip_addr));
      MEM_free(m_addr);
  }
  else
  {
      Address address;
      address.networkType = NETWORK_IPV6;

      NetworkGetInterfaceInfo(node, interfaceIndex, &address, NETWORK_IPV6);

      m_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);

      memcpy(&olsr->main_addr, m_addr, sizeof(union olsr_ip_addr));
      MEM_free(m_addr);
  }

  if(DEBUG_OUTPUT || DEBUG_OLSRV2)
  {
      paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
      olsr_printf("main_addr = %s\n",paddr);
      MEM_free(paddr);
  }

  union olsr_ip_addr* i_addr = NULL;
  int numberInterfaces = node->numberInterfaces;

  //init interface address
  olsr->iface_num = 1;
  olsr->iface_addr =
    (union olsr_ip_addr *)MEM_malloc
    (numberInterfaces*sizeof(union olsr_ip_addr));
  olsr->forward_info =
      (struct forward_infomation* )MEM_malloc
      (numberInterfaces*sizeof(struct forward_infomation));
  memset(olsr->forward_info, 0,
     numberInterfaces*sizeof(struct forward_infomation));
  olsr->forwardMsg = (void** )MEM_malloc(numberInterfaces*sizeof(void* ));
  memset(olsr->forwardMsg, 0, numberInterfaces*sizeof(void* ));

  //interfaces mapping  //wiss: 3am ne7jezlon ma7al bel memoire
  olsr->interfaceMappingOlsr =
    (olsr_u8_t* )MEM_malloc(sizeof(olsr_u8_t)*numberInterfaces);
  memset(olsr->interfaceMappingOlsr, 0, sizeof(olsr_u8_t)*numberInterfaces);
  olsr->interfaceMappingQualnet =
    (olsr_u8_t* )MEM_malloc(sizeof(olsr_u8_t)*numberInterfaces);
  memset(olsr->interfaceMappingQualnet, 0, sizeof(olsr_u8_t)*numberInterfaces);

  for(int i=0; i<numberInterfaces; i++)
  {
    olsr->interfaceMappingOlsr[i] = OLSR_INVALID_INTERFACE;
    olsr->interfaceMappingQualnet[i] = OLSR_INVALID_INTERFACE;
  }

  if(olsr_cnf->ip_version == AF_INET)
  {
      Address address;
      address.networkType = NETWORK_IPV4;
      address.interfaceAddr.ipv4 =
    NetworkIpGetInterfaceAddress(node, interfaceIndex);

      i_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);
      memcpy(&olsr->iface_addr[0], i_addr, sizeof(union olsr_ip_addr));
      MEM_free(i_addr);
  }
  else
  {
      Address address;
      address.networkType = NETWORK_IPV6;
      NetworkGetInterfaceInfo(node, interfaceIndex, &address, NETWORK_IPV6);

      i_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);
      memcpy(&olsr->iface_addr[0], i_addr, sizeof(union olsr_ip_addr));
      MEM_free(i_addr);
  }

  olsr->interfaceMappingQualnet[interfaceIndex] = 0;
  olsr->interfaceMappingOlsr[0] = (olsr_u8_t) interfaceIndex;


  if(DEBUG_OUTPUT || DEBUG_OLSRV2)
  {

      paddr = olsr_niigata_ip_to_string(olsr, &olsr->iface_addr[0]);
      olsr_printf("index = %d, iface_addr = %s\n", interfaceIndex, paddr);
      free(paddr);
      olsr_printf("************************************\n\n");
  }

  //init sim time
  RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);
  //init qualnet route
  RoutingOLSRv2_Niigata_InitQualnetRoute(node);

  // Set network router function
  NetworkIpSetRouterFunction(
        node,
        &OLSRRouterFunction,
        interfaceIndex);

  //init link layer notification
  if(olsr->qual_cnf->link_layer_notification)
  {
      if(olsr_cnf->ip_version == AF_INET)
      {
    NetworkIpSetMacLayerStatusEventHandlerFunction
      (node,
       RoutingOLSRv2_Niigata_LinkLayerNotificationHandler,
       interfaceIndex);
      }
      else
      {
      olsr_error("Link Layer Notification is not supported for IPv6!!\n");
      }
  }

  olsr->attached_net_addr = NULL;
  olsr->advNetAddrNum = 0;
  OLSRv2InitAttachedNetwork(node, nodeInput, interfaceIndex);

  //set timeout event
  timeoutMsg = MESSAGE_Alloc(node,
                 APP_LAYER,
                 APP_ROUTING_MPOLSRv2_NIIGATA,
                 MSG_APP_OLSRv2_NIIGATA_TimeoutTuples);
  MESSAGE_Send(node, timeoutMsg, (clocktype) olsr->qual_cnf->start_timeout);

  //set hello message send  event 
  helloPeriodicMsg = MESSAGE_Alloc(node,
                   APP_LAYER,
                   APP_ROUTING_MPOLSRv2_NIIGATA,
                   MSG_APP_OLSRv2_NIIGATA_PeriodicHello);

  MESSAGE_InfoAlloc(node, helloPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(helloPeriodicMsg) =
                                           (unsigned char)interfaceIndex;
  MESSAGE_Send(node,helloPeriodicMsg,(clocktype)olsr->qual_cnf->start_hello);

  //set tc message send event
  tcPeriodicMsg = MESSAGE_Alloc(node,
                APP_LAYER,
                APP_ROUTING_MPOLSRv2_NIIGATA,
                MSG_APP_OLSRv2_NIIGATA_PeriodicTc);

  MESSAGE_InfoAlloc(node, tcPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(tcPeriodicMsg) =
                                           (unsigned char)interfaceIndex;
  MESSAGE_Send(node,tcPeriodicMsg,(clocktype) olsr->qual_cnf->start_tc);

  //set queue update event        //wiss: men hon lal a5ir jdid 3al OLSR jiazy 3emlo
  	  	Message *msgUpdateQueueLength;
		clocktype delay;
  		msgUpdateQueueLength = MESSAGE_Alloc(node,
			APP_LAYER,
			APP_ROUTING_MPOLSRv2_NIIGATA,
			MSG_APP_OLSRv2_NIIGATA_UpdateQueueLength);

		delay = 1.005 * SECOND;
		MESSAGE_Send(node,msgUpdateQueueLength,delay);
}

void
RoutingMPOLSRv2_Niigata_AddInterface(Node *node,
                                   const NodeInput* nodeInput,
                                   int interfaceIndex,
                                   NetworkType networkType)
{
  struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
  olsrd_config* olsr_cnf = olsr->olsr_cnf;

   if ((olsr_cnf->ip_version == AF_INET && networkType == NETWORK_IPV6)
       ||
       (olsr_cnf->ip_version == AF_INET6 && networkType == NETWORK_IPV4))
   {
     ERROR_ReportError("Both IPv4 and IPv6 instance of"
      "OLSRv2-NIIGATA can not run simultaneously on a node");
   }

  union olsr_ip_addr* i_addr = NULL;

  Message *helloPeriodicMsg = NULL, *tcPeriodicMsg = NULL;
  char* paddr = NULL;

  olsr->iface_num++;

  if(olsr_cnf->ip_version == AF_INET)
  {
      Address address;
      address.networkType = NETWORK_IPV4;
      address.interfaceAddr.ipv4 =
    NetworkIpGetInterfaceAddress(node, interfaceIndex);

      i_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);
      memcpy(&olsr->iface_addr[olsr->iface_num-1], i_addr, sizeof(union olsr_ip_addr));
      MEM_free(i_addr);
  }
  else
  {
      Address address;
      address.networkType = NETWORK_IPV6;
      NetworkGetInterfaceInfo(node, interfaceIndex, &address, NETWORK_IPV6);

      i_addr = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr, address);
      memcpy(&olsr->iface_addr[olsr->iface_num-1], i_addr, sizeof(union olsr_ip_addr));
      MEM_free(i_addr);
  }

  olsr->interfaceMappingQualnet[interfaceIndex] = olsr->iface_num-1;
  olsr->interfaceMappingOlsr[olsr->iface_num-1] = (olsr_u8_t)interfaceIndex;

  if(DEBUG_OUTPUT || DEBUG_OLSRV2)
  {
    paddr = olsr_niigata_ip_to_string(olsr, &olsr->iface_addr[olsr->iface_num-1]);
    olsr_printf("index = %d, iface_addr = %s\n", interfaceIndex, paddr);
    free(paddr);
    olsr_printf("************************************\n\n");
  }

  //init attach network
  OLSRv2InitAttachedNetwork(node, nodeInput, interfaceIndex);

  //init link layer notification
  if(olsr->qual_cnf->link_layer_notification)
  {
      if(olsr_cnf->ip_version == AF_INET)
      {
    NetworkIpSetMacLayerStatusEventHandlerFunction
      (node,
       RoutingOLSRv2_Niigata_LinkLayerNotificationHandler,
       interfaceIndex);
      }
      else
      {
      olsr_error("Link Layer Notification: Not Suport IPv6!!\n");
      }
  }

  //set hello message send  event
  helloPeriodicMsg = MESSAGE_Alloc(node,
                   APP_LAYER,
                   APP_ROUTING_MPOLSRv2_NIIGATA,
                   MSG_APP_OLSRv2_NIIGATA_PeriodicHello);

  MESSAGE_InfoAlloc(node, helloPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(helloPeriodicMsg) =
                                               (unsigned char)interfaceIndex;
  MESSAGE_Send(node,helloPeriodicMsg,(clocktype)olsr->qual_cnf->start_hello);

  //set tc message send event
  tcPeriodicMsg = MESSAGE_Alloc(node,
                APP_LAYER,
                APP_ROUTING_MPOLSRv2_NIIGATA,
                MSG_APP_OLSRv2_NIIGATA_PeriodicTc);

  MESSAGE_InfoAlloc(node, tcPeriodicMsg, sizeof(unsigned char));
  *(unsigned char* )MESSAGE_ReturnInfo(tcPeriodicMsg) =
                                              (unsigned char) interfaceIndex;
  MESSAGE_Send(node, tcPeriodicMsg, (clocktype) olsr->qual_cnf->start_tc);
}

static
void RoutingOLSRv2_Niigata_PrintStat(Node *node)
{
    struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

    olsr_stat stat;
    char buf[MAX_STRING_LENGTH];

    stat = olsr->stat;

    sprintf(buf, "Hello Messages Received = %u",
        stat.numHelloReceived);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "Hello Messages Sent = %u",
        stat.numHelloGenerated);
    IO_PrintStat(
        node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "TC Messages Received = %u",
        stat.numTcReceived);
    IO_PrintStat(
        node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "TC Messages Generated = %u",
        stat.numTcGenerated);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "TC Messages Relayed = %u",
        stat.numTcRelayed);
    IO_PrintStat(
        node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "Total Messages Received = %u",
        stat.numMessageRecv);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "Total Messages Sent = %u",
        stat.numMessageSent);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "Total Bytes of Messages Received = %" TYPES_64BITFMT "d",
        stat.recvMsgSize);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);

    sprintf(buf, "Total Bytes of Messages Sent = %" TYPES_64BITFMT "d",
        stat.sendMsgSize);
    IO_PrintStat(
    node,
    "Application",
    "OLSRv2_NIIGATA",
    ANY_DEST,
    -1 /* instance Id */,
    buf);
}

void
RoutingMPOLSRv2_Niigata_Finalize(Node* node, int ifNum)
{
    struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

    if (!olsr->stat.statsPrinted)
    {
        RoutingOLSRv2_Niigata_PrintStat(node);
        olsr->stat.statsPrinted = OLSR_TRUE;

        if (DEBUG_OUTPUT || DEBUG_OLSRV2)
        {
            olsr_printf("\nFor Node Id: %d\n",node->nodeId);
            print_link_set(olsr);
            print_2neigh_set(olsr);
            print_mpr_set(olsr);
            print_mpr_selector_set(olsr);
            print_adv_neigh_set(olsr);
            print_assn_history_set(olsr);
            print_attached_set(olsr);
            print_relay_set(olsr);
            print_forward_set(olsr);
            print_proc_set(olsr);
            print_rcv_msg_set(olsr);
            print_topology_set(olsr);
       //     print_routing_set(olsr);
        }
    }
}


void
RoutingMPOLSRv2_Niigata_Layer(Node *node, Message *msg)
{
  struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;

  unsigned char index;
  char* paddr = NULL;

  switch (msg->eventType)
  {
  	  case MSG_APP_OLSRv2_NIIGATA_UpdateQueueLength:{
	  	Message *msgUpdateQueueLength;
		clocktype delay;

		msgUpdateQueueLength = MESSAGE_Alloc(node,
			APP_LAYER,
			APP_ROUTING_MPOLSRv2_NIIGATA,
			MSG_APP_OLSRv2_NIIGATA_UpdateQueueLength);

		delay = 500 * MILLI_SECOND;
		MESSAGE_Send(node,msgUpdateQueueLength,delay);

		int numOfQueuePackets = NetworkIpOutputQueueNumberInQueue(node, 0, FALSE, ALL_PRIORITIES); //wiss: determine le nombre de queue packets a une priorote donne
		int numOfQueueBytes = NetworkIpOutputQueueBytesInQueue(node, 0, FALSE, ALL_PRIORITIES);
		 //codexxx
 		if( numOfQueueBytes <= olsr->localqueuelen)
                        { olsr->localqueuelen = 0.8*olsr->localqueuelen + 0.2*numOfQueueBytes ;
                        }
		else{ olsr->localqueuelen = 0.5*numOfQueueBytes + 0.5*olsr->localqueuelen ;

                }
		//end codexxx 
		// if(DEBUG_OLSRV2){ printf("\n TEST NODE= %d have queuebyte= %d  \n",node->nodeId,numOfQueueBytes); }
		//olsr->localqueuelen = 0;//numOfQueueBytes ; //codexxx 
		
		char now[MAX_STRING_LENGTH];
		TIME_PrintClockInSecond(getSimTime(node), now);
	
	//	printf("Node Id: %d time: %s\tNumber of Packets in queue: %d\t bytes in queue: %d\n", 
	//		node->nodeId, now, numOfQueuePackets,numOfQueueBytes);
		
		break;
	  }
      case MSG_APP_FromTransport:
      {
      RoutingOLSRv2_Niigata_HandlePacket(node, msg);

      MESSAGE_Free(node, msg);
      break;
      }

      case MSG_APP_OLSRv2_NIIGATA_PeriodicHello:
      {
      RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);

      if(DEBUG_OLSRV2)
      {
          paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
          olsr_printf("Node %d with address %s encounter Hello Message Generation Event.\n",
             node->nodeId, paddr);
          MEM_free(paddr);
      }

      olsrd_config* olsr_cnf = olsr->olsr_cnf;

      NetworkType networkType;

      if (olsr_cnf->ip_version == AF_INET) {
         networkType = NETWORK_IPV4;
      }
      else
      {
         networkType = NETWORK_IPV6;
      }

      index = *(unsigned char* )MESSAGE_ReturnInfo(msg);
      // Do not consider  non-olsrv2 interfaces
      if ((NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_OLSRv2_NIIGATA)||(NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_MPOLSRv2_NIIGATA))
      {
          RoutingOLSRv2_Niigata_GenerateHelloMessage(
          node,
          (clocktype)olsr->qual_cnf->hello_interval,
          index);
      }

      MESSAGE_Free(node, msg);

      break;
      }

      case MSG_APP_OLSRv2_NIIGATA_PeriodicTc:
      {
      RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);

      if(DEBUG_OLSRV2)
      {
          paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
          olsr_printf("Node %d with address %s encounter TC Message Generation Event.\n",
             node->nodeId, paddr);
          MEM_free(paddr);
      }

      olsrd_config* olsr_cnf = olsr->olsr_cnf;
      NetworkType networkType;

      if (olsr_cnf->ip_version == AF_INET) {
         networkType = NETWORK_IPV4;
      }
      else
      {
         networkType = NETWORK_IPV6;
      }

      index = *(unsigned char* )MESSAGE_ReturnInfo(msg);
      // Do not consider  non-olsrv2 interfaces
      if ((NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_OLSRv2_NIIGATA)||(NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_MPOLSRv2_NIIGATA))
      {
          RoutingOLSRv2_Niigata_GenerateTcMessage(
          node,
          (clocktype)olsr->qual_cnf->tc_interval,
          index);
      }

      MESSAGE_Free(node, msg);
      break;
      }

      case MSG_APP_OLSRv2_NIIGATA_TimeoutForward:
      {
      RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);

      if(DEBUG_OLSRV2)
      {
          paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
          olsr_printf("Node %d with address %s encounter Timeout Event for Fowarding Messages.\n",
             node->nodeId, paddr);
          MEM_free(paddr);
      }

      olsrd_config* olsr_cnf = olsr->olsr_cnf;
      NetworkType networkType;

      if (olsr_cnf->ip_version == AF_INET) {
         networkType = NETWORK_IPV4;
      }
      else
      {
         networkType = NETWORK_IPV6;
      }

      index = *(unsigned char* )MESSAGE_ReturnInfo(msg);
      if ((NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_OLSRv2_NIIGATA)||(NetworkIpGetUnicastRoutingProtocolType(node, index, networkType)
          == ROUTING_PROTOCOL_MPOLSRv2_NIIGATA))
      {
          RoutingOLSRv2_Niigata_ForwardMessage(node, index);
          olsr->forwardMsg[index] = NULL;
      }

      MESSAGE_Free(node, msg);
      break;
      }

      case MSG_APP_OLSRv2_NIIGATA_TimeoutTuples:
      {
      RoutingOLSRv2_Niigata_UpdateCurrentSimTime(node);

      if(DEBUG_OLSRV2)
      {
          paddr = olsr_niigata_ip_to_string(olsr, &olsr->main_addr);
          olsr_printf("Node %d with address %s encounter Timeout Event for Tuple Validation.\n",
             node->nodeId, paddr);
          free(paddr);
      }

      RoutingOLSRv2_Niigata_CheckTimeoutTuples(node);

      MESSAGE_Free(node, msg);
      break;
      }

      default:
      {
      /* invalid message */
      ERROR_Assert(OLSR_FALSE, "Invalid switch value");
      break;
      }
  }
}

//--------------------------------------------------------------------------
// FUNCTION: OLSRRouterFunction
// added by Jiazi YI for MPOLSR
//Feb 2009
// PURPOSE:  Determine routing action to take for a the given data packet
//         1. for new data packets:   calculate the source route and add into the head of the packet.
//							set the nexthop in the IP table
//                                              mojette coding, etc.
//         2. for data packets to be forwarded: read the next hop in the source route and set the nexthop
//							route recovery
//         3. for data got to get destination:
//                                             mojette decoding, etc.
// ARGUMENTS: Received packet, destination of the packet, last hop address
// RETURN:   PacketWasRouted variable is TRUE if no further handling of
//           this packet by IP is necessary. Internally this variable is also
//           used to check route error packet. As route error transmission
//           function called this router function it will make packetWasRouted
//           as TRUE to mark it as a route error packet. It will be necessary
//           to identify route error packet for collecting statistics.
// ASSUMPTION: None
//--------------------------------------------------------------------------

void OLSRRouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL* packetWasRouted){

    BOOL isErrorPacket = *packetWasRouted;

//	if(DEBUG_OLSRV2)
//		printf("\n calling router function... %d\n",node->nodeId);
	
	struct olsrv2 *olsr = (struct olsrv2 *)node->appData.olsrv2;
	
	olsrv2_qualnet_config* olsr_cnf = olsr->qual_cnf;
	int numberOfpath = olsr_cnf->number_of_path;
	olsr_bool routerRecovery = olsr_cnf->route_recovery;
	olsr_bool ipSourceRouting = olsr_cnf->ip_source_routing;
	
	

	IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

	//    IpHeaderType* ipHdr = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
   // NodeAddress destAddr = ipHeader->ip_dst;
    NodeAddress srcAddr = ipHeader->ip_src;

	//qualnet address for transform. in olsrv2, all the ipv4 addresses used is different from qualnet
	Address qualnetDest, qualnetSrc;
	qualnetDest.networkType = qualnetSrc.networkType = NETWORK_IPV4;
	qualnetDest.interfaceAddr.ipv4 = destAddr;
	qualnetSrc.interfaceAddr.ipv4 = srcAddr;
	
	olsr_ip_addr *olsrDest, *olsrSrc;
	olsrDest = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetDest);
	olsrSrc = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetSrc);



	if (NetworkIpIsMyIP(node, ipHeader->ip_src) &&
        previousHopAddress == ANY_IP){
		//source node //wiss: awal ma mballach


		if (NetworkIpIsMyIP(node, ipHeader->ip_dst))
        {
            // Can't route a packet destined to itself
            *packetWasRouted = FALSE;
            return;
        }else{ //wiss: lezem a3mela route lal destination lakan lezem enu compute new multipath
			//compute new multipaths from source to dest
			//OLSRRouteComputation(node,src,dst)

			//if the route is out of date, we need to recompute
			if(get_flag(olsr,olsrDest->v4)){ //wiss: get flag betdel 3ala enu route out of date( enu sar lezem recompute)
				OLSRRouteComputation(
					node,
					msg,
					srcAddr,
					destAddr);
			}

			//get the source route info 
			m_rtable_t::iterator rt_it = lookup_route_entry(olsr,*olsrDest);

			//if there is no route, need to return
			if(rt_it == (*olsr->m_rtable).m_rt.end()){
				*packetWasRouted = FALSE;
				return;
			}
			
			for(int i = 0; i < olsr->pathCounter % numberOfpath; i++){
				rt_it++;
			}
			olsr->pathCounter ++;
/*
		if(DEBUG_OLSRV2){
		
			printf("\n The source route in the packet: \n");
			for (int i = 0;i<MAX_SR_LEN; i++){
				NodeAddress add_t = (*(rt_it->second->addr_[i])).v4;
				printf("%x \t" ,add_t);
				if (add_t == (*olsrDest).v4){
					break;
				}
			}
		}			*/

			//set the source route for the packet

			*packetWasRouted = TRUE;

			
			if (ipSourceRouting == OLSR_FALSE){
				//this part is for mp-olsr-no-ip-sr
				OLSRSetSourceRoute(node,msg,rt_it,(*olsrDest).v4,false);

				//get the next hop
				olsr_ip_addr nextHop;

				nextHop.v4 = OLSRGetNextHopFromSR(node, msg, (*olsrSrc).v4,(*olsrDest).v4);

				nextHop.v4 = GetQualnetIPv4FromOLSR(node,nextHop.v4); //need to convert the address

				//send out the packet
				ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

				NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,nextHop.v4);


				//end for mp-olsr-nsr //wiss: non source route
			}else{
				//this part is for IP source routing
				NodeAddress srAddressArray[MAX_SR_LEN];
				int numNewRouteAddresses;
				for (int i  = 0; i<MAX_SR_LEN; i++){
					srAddressArray[i] = (*(rt_it->second->addr_[i+1])).v4;
					if (srAddressArray[i] == (*olsrDest).v4){
						numNewRouteAddresses = i + 1;
						srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
						break;
					}
					srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
				}

				if(numNewRouteAddresses <= 9){
					//length of the path within 9 hops, can use source route directly
					NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute(
						node,
						msg,
						srAddressArray,
						numNewRouteAddresses,
					false);				
				}else{
					//length more than 9hops, forward to the next hop
					NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,srAddressArray[0]);

				}
				//end of part ip source routing
			}
		}
		
	}
	else if (NetworkIpIsMyIP(node, ipHeader->ip_dst)){
		//get to the dest  //wiss sar bel destination
//		if(DEBUG_OLSRV2)
//			printf("\n got to the dest... %d", node->nodeId);
		if (ipSourceRouting == OLSR_FALSE){
			//remove the multipath head, for mp-olsr-nsr
			int ipHeaderSize = IpHeaderSize(ipHeader);
			IpHeaderType origIpHeader;
			unsigned char *dataPtr;
			        

			memcpy(&origIpHeader, MESSAGE_ReturnPacket(msg),sizeof(IpHeaderType));

	        MESSAGE_RemoveHeader(node, msg, sizeof(IpHeaderType), TRACE_IP);

			dataPtr = (unsigned char*) MESSAGE_ReturnPacket(msg);

			//move the pointer to the NoOfNodes field
			dataPtr += 2*sizeof(olsr_u16_t);

			olsr_u16_t* tempNoOfNodes = (olsr_u16_t*)dataPtr;
			

			MESSAGE_ShrinkPacket(node, msg, SIZE_OF_MULTIPATH_COMMON_HEAD + *tempNoOfNodes * sizeof(NodeAddress));

			MESSAGE_AddHeader(node, msg, ipHeaderSize, TRACE_IP);

			// Change different fields of ip header
	    	ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
	    	memcpy(ipHeader, &origIpHeader, ipHeaderSize);
			IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),MESSAGE_ReturnPacketSize(msg));
			//end of mp-olsr-nsr
		}

	} else {
		//intermideate node  // wiss: la bel awal wala bel akhir... bel noss
	//	if(DEBUG_OLSRV2)
	//		printf("\n intermediate node... %d", node->nodeId);
		if(ipSourceRouting == OLSR_TRUE){
		//for mp-olsr-ip-sr
		if (FindAnIpOptionField(ipHeader, IPOPT_SSRR) == NULL){
			//is the packet has no source route, might come from olsr 
			if(get_flag(olsr,olsrDest->v4)){ //wiss: route timout---> get the route info
					OLSRRouteComputation(
						node,
						msg,
						srcAddr,
						destAddr);
			}
			//get the source route info
			m_rtable_t::iterator rt_it = lookup_route_entry(olsr,*olsrDest);

			//if there is no route, need to return
			if(rt_it == (*olsr->m_rtable).m_rt.end()){
				*packetWasRouted = FALSE;
				return;
			}
			*packetWasRouted = TRUE;

			NodeAddress srAddressArray[MAX_SR_LEN];
			int numNewRouteAddresses;
			for (int i  = 0; i<MAX_SR_LEN; i++){
				srAddressArray[i] = (*(rt_it->second->addr_[i+1])).v4;
				if (srAddressArray[i] == (*olsrDest).v4){
					numNewRouteAddresses = i + 1;
					srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
					break;
				}
				srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
			}
			if(numNewRouteAddresses <= 9){
				//length of the path within 9 hops, can use source route directly
				NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute(
					node,
					msg,
					srAddressArray,
					numNewRouteAddresses,
				false);				
			}else{
				//length more than 9hops, forward to the next hop
				NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,srAddressArray[0]);

			}

		}else{
			//wiss: ici FindAnIpOptionField(ipHeader, IPOPT_SSRR) != NULL
			//route recovery, for ip-sr
			//if there is no need for route recovery, no need to treat the packet here
			if (routerRecovery == OLSR_TRUE){
				IpOptionsHeaderType *ipOptions =
        			FindAnIpOptionField(ipHeader, IPOPT_SSRR);
				if (ipOptions->ptr < ipOptions->len) {
			        // Extract Next Address
			        // The definition of "ptr" seems to number 1 as the
			        // first byte of the the options field.
			       	char *routeRawAddressBytes = (char *) ipOptions + ipOptions->ptr - 1;
			        NodeAddress nextHop, nextHopQualnet;

			        // Done because the address bytes may be out of alignment
			        // on certain processors.

			        memcpy(&nextHop, routeRawAddressBytes, sizeof(NodeAddress));

					nextHopQualnet = GetQualnetIPv4FromOLSR(node, nextHop);

					//for route recovery, check the neighbor
					bool nextHopFlag = false;
					OLSR_LIST_ENTRY *tmp_A = NULL;
					tmp_A = olsr->link_set.head;
					OLSR_LINK_TUPLE *link_data = NULL;

		  			while(tmp_A){
		      			link_data = (OLSR_LINK_TUPLE *)tmp_A->data;

						if (link_data->L_neighbor_iface_addr.v4 == nextHopQualnet){
							nextHopFlag = true;
							break;
						}
						tmp_A = tmp_A->next;
					}

					//nextHopFlag = false; //for debug only

					if (nextHopFlag == false){
						//next hop in the source route is not the neighbor, need to recompute the path
						if(DEBUG_OLSRV2){
							printf("\n Link break at node %d (0X%x), to next hop %x, the destination is %x, message seq is %d\n",
							node->nodeId,node->nodeId,nextHopQualnet,destAddr,msg->sequenceNumber);

						}
						srcAddr = NetworkIpGetInterfaceAddress(node,DEFAULT_INTERFACE);
						if(get_flag(olsr,olsrDest->v4)){
							OLSRRouteComputation(
								node,
								msg,
								srcAddr,
								destAddr);
						}
						//get the source route info 
						m_rtable_t::iterator rt_it = lookup_route_entry(olsr,*olsrDest);

						//if there is no route, need to return
						if(rt_it == (*olsr->m_rtable).m_rt.end()){
							*packetWasRouted = FALSE;
							return;
						}

						//loop check

						//first, read the source route infomation in the original head
						std::vector<NodeAddress> sourceRoute;  //the vecotr to save the info
						int numberOfHops = (ipOptions->len - 4) / 4;   //get the number of hops

						sourceRoute.push_back(olsrSrc->v4); 
						//add the source node, because the ip SR don't save the source info in the SR head

						NodeAddress olsrPreviousHopAddress = GetOLSRFromQualnetIPv4(node, previousHopAddress);
						sourceRoute.push_back(olsrPreviousHopAddress); // also add the previous hop address
						char *srptr = (char *) ipOptions + 4 -1; //move the pointer
						for (int i = 0; i< numberOfHops; i++){

							NodeAddress tempAddr;
							memcpy(&tempAddr, srptr, sizeof(NodeAddress));

							sourceRoute.push_back(tempAddr);
							srptr += sizeof(NodeAddress);

						}

						//second, verify that if the new route uses old nodes. 

						//std::vector<NodeAddress>::iterator old_it;
						bool sr_flag = true;	//if flag is false, means there is old nodes in the sourec route
						int hopcount;

						for (int j = 1; j < numberOfpath; j ++){
							for(int i = 1; i<MAX_SR_LEN;i++){
								NodeAddress tempAddress = (*(rt_it->second->addr_[i])).v4;
								NodeAddress tempQualAddress = GetQualnetIPv4FromOLSR(node,tempAddress);

								for(std::vector<NodeAddress>::iterator old_it = sourceRoute.begin(); old_it < sourceRoute.end(); old_it++){
								//	printf("** %x, %x**\n",*old_it,tempAddress);
									if ( *old_it == tempAddress){
										sr_flag = false;
										break;
									}
								}
								if (tempQualAddress == ipHeader->ip_dst){
									hopcount = i;
									break;
								}

							}

							//if the new route uses old nodes, we need to change to another route.
							if(sr_flag == false){
								rt_it ++;
								printf("POSSIBILITY OF LOOPS, CHANGE TO ANOTHER ROUTE\n");
								sr_flag = true; //reset the flag
								if (j == numberOfpath - 1 ){
									//there is loop in all the paths, so it's better to drop the packet here
									//by setting ttl= 1;
									ipHeader->ip_ttl =1;
								}

							}else
								break;

						}						


						//end of loop check

						olsr->pathCounter ++;
						*packetWasRouted = TRUE;

						//set the ip source route
						NodeAddress srAddressArray[MAX_SR_LEN];
						int numNewRouteAddresses;
						for (int i	= 0; i<MAX_SR_LEN; i++){
							srAddressArray[i] = (*(rt_it->second->addr_[i+1])).v4;
							if (srAddressArray[i] == (*olsrDest).v4){
								numNewRouteAddresses = i + 1;
								srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
								break;
							}
							srAddressArray[i]= GetQualnetIPv4FromOLSR(node,srAddressArray[i]);
						}
						
						if(numNewRouteAddresses < 9){
							//length of the path within 9 hops, can use source route directly
						/*for debug	
							IpOptionsHeaderType *ipOption = FindAnIpOptionField(ipHeader, IPOPT_SSRR);
							int oldHeaderSize = IpHeaderSize(ipHeader);
						    int oldIpOptionSize = ipOption->len;
						    int deltaOptionSize = numNewRouteAddresses*4 ;
						    int newHeaderSize = deltaOptionSize + 4;
							printf("length of SR header: %d\n",newHeaderSize);*/
							
							NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute(
								node,
								msg,
								srAddressArray,
								numNewRouteAddresses,
							true); 			
						}else{ 
							//length more than 9hops, forward to the next hop
							NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,srAddressArray[0]);
						
						}
	
					}
				
				}else{ 
					//wiss: ipOptions->ptr >= ipOptions->len
					// QualNet should not create corrupted source routes.

			        ERROR_ReportError("Source route option in IP header corrupted");

			        // Re-enable if corrupted source routes are possible.
			        // NetworkDataIp *ip = (NetworkDataIp *)
			        //                           node->networkData.networkVar;
			        //
			        // Increment stat for number of IP datagrams discarded because
			        // of header errors (e.g., checksum error, version number
			        // mismatch, TTL exceeded, etc.).
			        //
			        //ip->stats.ipInHdrErrors++;
			        //
			        //MESSAGE_Free(node, msg);
			    }//if//
			}//wiss: routerrecovery !=OLSR_true
		}
		

		//end for mp-olsr-ip-sr
		}else{

		//wiss: ipSourceRouting != OLSR_TRUE
		//read the source route info, for mp-olsr-nip-sr
		*packetWasRouted = TRUE;
		olsr_ip_addr nextHop;

 		nextHop.v4 = OLSRGetNextHopFromSR(node, msg, (*olsrSrc).v4,(*olsrDest).v4);
				//	nextHop.v4 = 0x30000c0;
				//	nextHop.v4 = 0xc0000003;

		//route recovery
		if (routerRecovery == OLSR_TRUE){
			//for route recovery, check the neighbor
			bool nextHopFlag = false;
			OLSR_LIST_ENTRY *tmp_A = NULL;
			tmp_A = olsr->link_set.head;
			OLSR_LINK_TUPLE *link_data = NULL;

  			while(tmp_A){
      			link_data = (OLSR_LINK_TUPLE *)tmp_A->data;

				if (link_data->L_neighbor_iface_addr.v4 == nextHop.v4){
					nextHopFlag = true;
					break;
				}
				tmp_A = tmp_A->next;
			}

			if(nextHopFlag == false){

				//for route recovery, recompute the route
				if(DEBUG_OLSRV2){
					printf("\n Link break at node %d (0X%x), to next hop %x, the destination is %x, message seq is %d\n",
						node->nodeId,node->nodeId,nextHop.v4,destAddr,msg->sequenceNumber);

				}
				srcAddr = NetworkIpGetInterfaceAddress(node,DEFAULT_INTERFACE);
				if(get_flag(olsr,olsrDest->v4)){
					OLSRRouteComputation(
						node,
						msg,
						srcAddr,
						destAddr);
				}
				

				//get the source route info
				m_rtable_t::iterator rt_it = lookup_route_entry(olsr,*olsrDest);

				//if there is no route, need to return
				if(rt_it == (*olsr->m_rtable).m_rt.end()){
					*packetWasRouted = FALSE;
					return;
				}

				//for route recovery, to avoid the "ping-pong" affect, we need to check the new route
				// the idea is to verify if the new route uses the node that the packet has passed

				//first, read the original source route in the packet
				std::vector<NodeAddress> sourceRoute;
				OLSRGetSourceRoute(node,msg,&sourceRoute);
				printf("%x\n",(sourceRoute).back());

				//second, verify that if the new route uses old nodes. 

				//std::vector<NodeAddress>::iterator old_it;
				bool sr_flag = true;	//if flag is false, means there is old nodes in the sourec route
				int hopcount;

				for (int j = 1; j < numberOfpath; j ++){
					for(int i = 1; i<MAX_SR_LEN;i++){
						NodeAddress tempAddress = (*(rt_it->second->addr_[i])).v4;
						NodeAddress tempQualAddress = GetQualnetIPv4FromOLSR(node,tempAddress);

						for(std::vector<NodeAddress>::iterator old_it = sourceRoute.begin(); old_it < sourceRoute.end(); old_it++){
						//	printf("** %x, %x**\n",*old_it,tempAddress);
							if ( *old_it == tempAddress){
								sr_flag = false;
								break;
							}
						}
						if (tempQualAddress == ipHeader->ip_dst){
							hopcount = i;
							break;
						}

					}

					//if the new route uses old nodes, we need to change to another route.
					if(sr_flag == false){
						rt_it ++;
						printf("POSSIBILITY OF LOOPS, CHANGE TO ANOTHER ROUTE\n");
						sr_flag = true; //reset the flag
						if (j == numberOfpath - 1 ){
							//there is loop in all the paths, so it's better to drop the packet here
							//by setting ttl= 1;
							ipHeader->ip_ttl = 1;
						}

					}else
						break;

				}
				//end of loop check
				

	//			printf("%d **\n",hopcount);
				//this code need to be modified 
				if (hopcount > MAX_SR_LEN){
					*packetWasRouted = FALSE;
					printf("LENGTH OUT OF RANGE\n");
	
					return;
				}

				//reset the source route head
			//	printf("%d\n",IpHeaderSize(ipHeader));
				int numberOfHops = OLSRSetSourceRoute(node,msg,rt_it,(*olsrDest).v4,true);

				*packetWasRouted = TRUE;

				//get the next hop
				//olsr_ip_addr nextHop;

				(*olsrSrc).v4 = GetOLSRFromQualnetIPv4(node,srcAddr);

				nextHop.v4 = OLSRGetNextHopFromSR(node, msg, (*olsrSrc).v4,(*olsrDest).v4);

				//send out the packet
				ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

			}

		}

		//need to transfer the address from olsr to qualnet
		nextHop.v4 = GetQualnetIPv4FromOLSR(node,nextHop.v4);
		//send out the packet
		NetworkIpSendPacketToMacLayer(node,msg,DEFAULT_INTERFACE,nextHop.v4);

		//end for no-ip-sr
		}
	}
	
}


//codexxx
int Get_queue_length(struct olsrv2 *olsr, union olsr_ip_addr *Node_add)
{
	
  struct queue_info *tempo= NULL ;
  OLSR_LIST_ENTRY *queueEntry = NULL;
  int defaut=0;

	if(olsr->queue_set.numEntry == 0) 
		{ // liste vide
			return defaut;
		  
		  
	  }else{ // liste pleine => cherhcer l'addresse s'il existe
	  queueEntry = olsr->queue_set.head ;
		while(queueEntry != NULL)  /////
			{ //if(DEBUG_OLSRV2){ printf("\n hayda test  %d ",((queue_info *)queueEntry->data)->Qlength);}
			tempo = (queue_info *)queueEntry->data ;
			if(!cmp_ip_addr(olsr,&tempo->orig_IP,Node_add))
			{  // on a trouver cet originator IP ds la liste alors return le queuelength correspondant et sortir de la boucle
				//if(DEBUG_OLSRV2){ printf("\n fet hon  %d ",((queue_info *)queueEntry->data)->Qlength);}
			   return tempo->Qlength ;
			  

			}
		queueEntry = queueEntry->next ;
	  }
		// ici c.a.d l'addresse n'est pas trouve dans la liste => return le default
		return defaut ;
			
		
	  }

}

// end codexxx



//codexxx

float Set_Weight(std::map<olsr_u32_t, Dijkstra_node*> node_map,union olsr_ip_addr *dest_add,union olsr_ip_addr *last_add)
{ 	//return 1 ;
	map<olsr_u32_t, Dijkstra_node*>::iterator node_it ;
	int n1, n2;
	float tempval;

		node_it = node_map.find(dest_add->v4);
		n1 = (*(*node_it).second).QueueInByte;

		node_it = node_map.find(last_add->v4);
		n2 = (*(*node_it).second).QueueInByte;

		tempval = (n1 + n2)/2 ;
		tempval= 64*(tempval/50000)+1 ;
		
		return tempval ;		

}

//end codexxx




void OLSRRouteComputation(
	Node * node,
	Message * msg,
	NodeAddress srcAddr,
	NodeAddress destAddr){

	struct olsrv2 *olsr =
    (struct olsrv2 *)node->appData.olsrv2;
	olsrv2_qualnet_config* olsr_cnf = olsr->qual_cnf;

	OLSR_LIST_ENTRY *tmp_A = NULL, *tmp_B = NULL;
	OLSR_LINK_TUPLE *link_data = NULL, *link_data_2hop = NULL;
  	OLSR_2NEIGH_TUPLE *two_nei_data = NULL;

	int numberOfpath = olsr_cnf->number_of_path;

	bool type_flag = false;

	//qualnet address for transform. in olsrv2, all the ipv4 addresses used is different from qualnet
	Address qualnetDest, qualnetSrc;
	qualnetDest.networkType = qualnetSrc.networkType = NETWORK_IPV4;
	qualnetDest.interfaceAddr.ipv4 = destAddr;
	qualnetSrc.interfaceAddr.ipv4 = srcAddr;
	
	olsr_ip_addr *olsrDest, *olsrSrc;
	olsrDest = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetDest);
	olsrSrc = RoutingOLSRv2_Niigata_GetOlsrv2_Niigata_Address(olsr,qualnetSrc);
	
	
	olsr_time_t time;
	get_current_time(olsr, &time);

	//remove the old entries in the routing table
	rm_rt_entry(olsr, *olsrDest);  // wiss: remove the "olsrDest" from the routing table
	

	// 1 gather all the network topology info, including the info 
	// in the linkset, two_neighSet and topology set
	// construct the graph of the network, include the node map and the arc map

	std::map<olsr_u32_t, Dijkstra_node*> node_map;
	std::vector<Arc_map_tuple*> arc_map;

	// 1.0 add the node itself to the node map
	pair<map<olsr_u32_t,Dijkstra_node*>::iterator,bool> ret;   //wiss: ma fhemet chou hel jemle
	Dijkstra_node* d_node = new Dijkstra_node;
	(*d_node).addr_.v4 = (*olsrSrc).v4;
	(*d_node).weight_ = MAX_WEIGHT;
	(*d_node).node_type_ = T_TYPE;
    (*d_node).QueueInByte = Get_queue_length(olsr, &(*d_node).addr_ );  //codexxx
    	
	ret = node_map.insert(pair<olsr_u32_t,Dijkstra_node*>((*d_node).addr_.v4, d_node));
	
	
	// 1.1  for the link set 
	tmp_A = olsr->link_set.head;

  	while(tmp_A)
  	{
      	link_data = (OLSR_LINK_TUPLE *)tmp_A->data;
      	if(get_link_status(time,
             link_data->L_SYM_time,
             link_data->L_ASYM_time,
             link_data->L_LOST_LINK_time) == SYMMETRIC ||
             get_link_status(time,
             link_data->L_SYM_time,
             link_data->L_ASYM_time,
             link_data->L_LOST_LINK_time) == ASYMMETRIC
             ){  // wiss: hon link status symmetric ou asymmetric
	      	if(DEBUG_OLSRV2)
	      	{
	 //         printf("------gathering Link set info---------%x\t %x\t \n", 
		//	  	link_data->L_local_iface_addr.v4, link_data->L_neighbor_iface_addr.v4);
	      	}

			//address transformation

			if (!cmp_ip_addr(olsr,olsrDest, &link_data->L_neighbor_iface_addr)){
				//the dest is the neighbor //wiss: here el dest is the neighbor
				// wiss: add to routing table directly...
				OLSR_m_rt_entry* m_rt_entry = new OLSR_m_rt_entry;
				m_rt_entry->dest = &link_data->L_neighbor_iface_addr;
				m_rt_entry->addr_[0] = &link_data->L_local_iface_addr;
				m_rt_entry->addr_[1] = &link_data->L_neighbor_iface_addr;

				for (int i = 0;i < numberOfpath; i++){
					add_rt_entry(olsr,m_rt_entry);
				}
				set_flag(olsr, olsrDest->v4, false);
				
				return;
			}
			// wiss: hon el neighbor mano el destination...
			//add the node to node map 
			Dijkstra_node* d_node_temp = new Dijkstra_node;
			(*d_node_temp).addr_ = link_data->L_neighbor_iface_addr;
			(*d_node_temp).weight_ = MAX_WEIGHT;
			(*d_node_temp).node_type_ = T_TYPE;
			(*d_node_temp).QueueInByte = Get_queue_length(olsr, &(*d_node_temp).addr_ );  //codexxx
			 //if(DEBUG_OLSRV2){ printf("\n hayda test x  %i ", (*d_node_temp).QueueInByte ) ; }
			
			ret = node_map.insert(pair<olsr_u32_t, Dijkstra_node*>((*d_node_temp).addr_.v4,d_node_temp));
			//insert failed, maybe because the node has been existed //wiss: fa khalas menkebba bima enu mawjoude
			if (ret.second == false)  //wiss: chou ya3ni ret.second ??.... rep : second = true if the new element was inserted (btw el first ya3ni iterator pointing)
				MEM_free(d_node_temp);

			//add the arc to arc map
			Arc_map_tuple* a_tuple = new Arc_map_tuple;
			(*a_tuple).A_last_addr_ = *olsrSrc;
			(*a_tuple).A_dest_addr_ = link_data->L_neighbor_iface_addr;
			(*a_tuple).A_original_weight_ = 1;
			(*a_tuple).A_weight_ = Set_Weight( node_map,&(*a_tuple).A_last_addr_,&(*a_tuple).A_dest_addr_); //codexxx

			if(check_arc_tuple(&arc_map, a_tuple)){  // wiss: check if it exists
				MEM_free(a_tuple);
			}else{
				arc_map.push_back(a_tuple);		//wiss: menzidou 3al arc_map
			}

			//for an oriented arc, it's better to add the reverse arc also
			a_tuple = new Arc_map_tuple;
			(*a_tuple).A_last_addr_ = link_data->L_neighbor_iface_addr;
			(*a_tuple).A_dest_addr_ = *olsrSrc;
			(*a_tuple).A_original_weight_ = 1;
			(*a_tuple).A_weight_ = Set_Weight( node_map,&(*a_tuple).A_last_addr_,&(*a_tuple).A_dest_addr_); //codexxx

			if(check_arc_tuple(&arc_map, a_tuple)){
				MEM_free(a_tuple);
			}else{
				arc_map.push_back(a_tuple);	
			}

      	}

      tmp_A = tmp_A->next;
  	}
	// wiss: hon khlasna men el jiran mnente2el 3al two hops
	// 1.2 and then, for the two-hop neighbor set

	
	for(int hash_index = 0; hash_index < HASHSIZE; hash_index++){
		tmp_A = olsr->two_neigh_set[hash_index].list.head;

		while(tmp_A){

			//read the n2 tuple
			OLSR_2NEIGH_TUPLE* n2_tuple = (OLSR_2NEIGH_TUPLE *)tmp_A->data;


			//if the dest is the two hop neighbor, no need to do it anymore, add the path directly to the routing table
			if(!cmp_ip_addr(olsr,olsrDest, &n2_tuple->N2_2hop_iface_addr)){
				printf("2 hop neighbor is the dest\n");

				OLSR_m_rt_entry* m_rt_entry = new OLSR_m_rt_entry;
				m_rt_entry->dest = olsrDest;
				m_rt_entry->addr_[0] = &n2_tuple->N2_local_iface_addr;
				m_rt_entry->addr_[1] = &n2_tuple->N2_neighbor_iface_addr;
				m_rt_entry->addr_[2] = &n2_tuple->N2_2hop_iface_addr;

				for (int i = 0;i < numberOfpath; i++){
					add_rt_entry(olsr,m_rt_entry);
				}
				set_flag(olsr, olsrDest->v4, false);
				
				return;

			}
			// wiss: el destination manno el 2 hop neighbor 
			//add the node to node map
			Dijkstra_node* d_node_temp = new Dijkstra_node;
			// wiss: menzid jar el jar 3al nodes
			(*d_node_temp).addr_ = (*n2_tuple).N2_2hop_iface_addr;
			(*d_node_temp).weight_ = MAX_WEIGHT;
			(*d_node_temp).node_type_ = T_TYPE;
			(*d_node_temp).QueueInByte = Get_queue_length(olsr, &(*d_node_temp).addr_ );
			//if(DEBUG_OLSRV2){ printf("\n hayda test x  %i ", (*d_node_temp).QueueInByte ) ; }
			
			ret = node_map.insert(pair<olsr_u32_t, Dijkstra_node*>((*d_node_temp).addr_.v4,d_node_temp));
				//insert failed, maybe because the node has been existed
			if (ret.second == false)
				MEM_free(d_node_temp);

			d_node_temp = new Dijkstra_node;
			(*d_node_temp).addr_ = (*n2_tuple).N2_neighbor_iface_addr;
			(*d_node_temp).weight_ = MAX_WEIGHT;
			(*d_node_temp).node_type_ = T_TYPE;			// wiss: menzid el jar 3al nodes
			(*d_node_temp).QueueInByte = Get_queue_length(olsr, &(*d_node_temp).addr_ );
			//if(DEBUG_OLSRV2){ printf("\n hayda test x  %i ", (*d_node_temp).QueueInByte ) ; }
		
			ret = node_map.insert(pair<olsr_u32_t, Dijkstra_node*>((*d_node_temp).addr_.v4,d_node_temp));
				//insert failed, maybe because the node has been existed
			if (ret.second == false)
				MEM_free(d_node_temp);

			//add the arc to arc map
			Arc_map_tuple* a_tuple = new Arc_map_tuple;
			(*a_tuple).A_last_addr_ = (*n2_tuple).N2_neighbor_iface_addr;
			(*a_tuple).A_dest_addr_ = (*n2_tuple).N2_2hop_iface_addr;
			(*a_tuple).A_original_weight_ = 1;
			(*a_tuple).A_weight_ = Set_Weight( node_map,&(*a_tuple).A_last_addr_,&(*a_tuple).A_dest_addr_); //codexxx

			if(check_arc_tuple(&arc_map, a_tuple)){
				MEM_free(a_tuple); // wiss: iza mawjoud deja za77et
			}else{
				arc_map.push_back(a_tuple);	  //wiss: iza mech mawjoud pushback (ya3ni add a new element at the end of the vector)
			}

			// wiss: el arc men el etijeh el mou3akes
			a_tuple = new Arc_map_tuple;
			(*a_tuple).A_last_addr_ = (*n2_tuple).N2_2hop_iface_addr;
			(*a_tuple).A_dest_addr_ = (*n2_tuple).N2_neighbor_iface_addr;
			(*a_tuple).A_original_weight_ = 1;
			(*a_tuple).A_weight_ = Set_Weight( node_map,&(*a_tuple).A_last_addr_,&(*a_tuple).A_dest_addr_); //codexxx

			if(check_arc_tuple(&arc_map, a_tuple)){
				MEM_free(a_tuple);
			}else{
				arc_map.push_back(a_tuple);		
			}
			
			tmp_A = tmp_A->next;
		}

	}

	// wiss: hon khalasna men el 2 hop neighbors
	// 1.3 for the topology set
	for(int hash_index = 0; hash_index < HASHSIZE; hash_index++){
		tmp_A = olsr->topology_set[hash_index].list.head;

		while(tmp_A){
			OLSR_TOPOLOGY_TUPLE* topo_tuple = (OLSR_TOPOLOGY_TUPLE*)tmp_A->data;

			//add the node to node map //wiss: add the destination node to node map and last node...
			Dijkstra_node* d_node_temp = new Dijkstra_node;
			// wiss: menzid el destination 3al nodes
			(*d_node_temp).addr_ = (*topo_tuple).T_dest_iface_addr;
			(*d_node_temp).weight_ = MAX_WEIGHT;
			(*d_node_temp).node_type_ = T_TYPE;	
			(*d_node_temp).QueueInByte = Get_queue_length(olsr, &(*d_node_temp).addr_ ); //codexxx

			
			ret = node_map.insert(pair<olsr_u32_t, Dijkstra_node*>((*d_node_temp).addr_.v4,d_node_temp));
				//insert failed, maybe because the node has been existed
			if (ret.second == false){
				MEM_free(d_node_temp);
			}
			
			d_node_temp = new Dijkstra_node;
			(*d_node_temp).addr_ = (*topo_tuple).T_last_iface_addr;
			(*d_node_temp).weight_ = MAX_WEIGHT;
			(*d_node_temp).node_type_ = T_TYPE;
			(*d_node_temp).QueueInByte = Get_queue_length(olsr, &(*d_node_temp).addr_ ); //codexxx
			
			// wiss: menzid el last iface address 3al nodes
			
			ret = node_map.insert(pair<olsr_u32_t, Dijkstra_node*>((*d_node_temp).addr_.v4,d_node_temp));
				//insert failed, maybe because the node has been existed
			if (ret.second == false)
				MEM_free(d_node_temp);

			//add the arc to arc map
			Arc_map_tuple* a_tuple = new Arc_map_tuple;
			(*a_tuple).A_last_addr_ = (*topo_tuple).T_last_iface_addr;
			(*a_tuple).A_dest_addr_ = (*topo_tuple).T_dest_iface_addr;
			(*a_tuple).A_original_weight_ = 1;  
			(*a_tuple).A_weight_ = Set_Weight( node_map,&(*a_tuple).A_last_addr_,&(*a_tuple).A_dest_addr_); //codexxx

			if(check_arc_tuple(&arc_map, a_tuple)){
				MEM_free(a_tuple);
			}else{
				arc_map.push_back(a_tuple);		
			}

			tmp_A = tmp_A->next;

		}

	}

	// wiss: hon khalasna phase el te3beye... bedna n machi el algorithm ( bass bel node ba3ed ma 3abayna el pre-addr)

	// 2 followed by the Dijkstra algorithm	
	map<olsr_u32_t, Dijkstra_node*>::iterator n_it, n_it_d;
	Dijkstra_node *node_n, *node_t;


	for(int i = 0; i < numberOfpath; i++) {

				//reset all the nodes for next rotation  // wiss: ba3ed ma tkawanet el node map initialize el kell 3ala T_TYPE  w MAX_WEIGHT
			for (n_it = node_map.begin(); n_it != node_map.end(); n_it ++){
				node_n = (*n_it).second;
				(*node_n).node_type_ = T_TYPE;
				(*node_n).weight_ = MAX_WEIGHT;
			}


/*			if(DEBUG_OLSRV2)
	{
		printf("\n----------node map---------\n");
		std::map<olsr_u32_t, Dijkstra_node*>::iterator n_it;
		for (n_it = node_map.begin(); n_it != node_map.end(); n_it ++){
			printf("%x\t %f |", (*n_it).first, (*(*n_it).second).weight_);
		}

		printf("\n-----------arc map----------\n");
		std::vector<Arc_map_tuple*>::iterator a_it;
		for (a_it = arc_map.begin(); a_it != arc_map.end(); a_it++){
			printf("%x --> %x, %f\n", (*a_it)->A_last_addr_.v4,(*a_it)->A_dest_addr_.v4, (*a_it)->A_weight_);
		}
		printf("-----------------------------------\n");
					
	}*/
		n_it = node_map.find(olsrSrc->v4);
		(*(*n_it).second).node_type_ = P_TYPE;
		(*(*n_it).second).weight_ = 0; // wiss: el source men7etelou el weight = 0 wel type P_TYPE

		for ( ; ; ){
			//1. renew all the weight_ of T type nodes

			for (std::vector<Arc_map_tuple*>::iterator it = arc_map.begin();
					it != arc_map.end(); it++){
				for(n_it = node_map.begin(); n_it != node_map.end(); n_it ++){
					Dijkstra_node *node_s, *node_d;

					node_s = (*n_it).second;

					if((*node_s).node_type_ == P_TYPE 
							&& !cmp_ip_addr(olsr, &((*node_s).addr_), &((*it)->A_last_addr_))){
						// wiss: ici ya3ni bedeyet el arc  moutatabe2 ma3 el ip wel node de type P
						//n_it_d = node_map.find((*node_s).addr_.v4);
						// wiss: trouver la destination de cet arc trouve
						n_it_d = node_map.find((*it)->A_dest_addr_.v4); // wiss: fatech 3al node yalli correspond 3a niheyet el arc
						node_d = (*n_it_d).second;

						if((*node_s).weight_ + (*it)->A_weight_ < (*node_d).weight_){
							(*node_d).weight_ = (*node_s).weight_ + (*it)->A_weight_;
							(*node_d).pre_addr_ = (*node_s).addr_;  // wiss: set pre_address 
						}
						
					}
						
				}
			}

			//2. find the T type node with the min weight_, and set it to P type
			int counter = 0;
			node_t = (*node_map.begin()).second;
			for(n_it = node_map.begin(); n_it != node_map.end(); n_it++){
				node_n = (*n_it).second;		
				if (counter == 0 && (*node_n).node_type_ == P_TYPE)
					continue;
				if((*node_n).node_type_ == T_TYPE){
					if(counter == 0)
							node_t = node_n;
					if((*node_t).weight_ > (*node_n).weight_){
						node_t = node_n;  // wiss: ya3ni bel niheye byetla3 3enna node_t howe de type T w 3endou asghar wheight
		//				printf("%f\t %f\n",(*node_t).weight_, (*node_n).weight_);
					}
				}
				counter ++;				
			}

			if((*node_t).weight_ >= MAX_WEIGHT){
				if(DEBUG_OLSRV2)
					printf("there is no route found from %x to %x!!\n", olsrSrc->v4,olsrDest->v4);
				type_flag = false;
				return;
			}

			(*node_t).node_type_ = P_TYPE;			

			//3. found the route to the destination	?
	//		printf("%x %x\n", (*node_t).addr_.v4, (*olsrDest).v4);
			if(!cmp_ip_addr(olsr,&(*node_t).addr_, olsrDest)){
				if(DEBUG_OLSRV2){
					printf("I got one! path No %d from %x to %x\n", i+1, olsrSrc->v4, olsrDest->v4);
									
				}
				type_flag = true;
				break; //wiss: la2an iza la2 bedoou yerja3 yebrom 3a path wa iz la2a el path el matloub
			}

			//check if all the node have been extended
			type_flag = false;
			for(n_it = node_map.begin(); n_it != node_map.end(); n_it ++){
				node_n = (*n_it).second;
				if((*node_n).node_type_ == T_TYPE){
					type_flag = true;
				}
			}

			if(type_flag == false){
				if(DEBUG_OLSRV2)
					printf("there is no route found from %x to %x!!\n", olsrSrc->v4,olsrDest->v4);
				break;
			}
			
		}
		
		//construct the routing entry
		if(type_flag == false)
			break;

		OLSR_m_rt_entry* m_rt_entry = new OLSR_m_rt_entry;
		std::vector<olsr_ip_addr> addr_stack;
		do {
			olsr_ip_addr* t_sr_addr_ = new olsr_ip_addr;
			(*t_sr_addr_) = (*node_t).addr_;
/*
			//renew the weight of the topology tuple for multipath algorithm
			if(!addr_stack.empty()){
				olsr_ip_addr preHop = addr_stack.back();
				
				for(std::vector<Arc_map_tuple*>::iterator it = arc_map.begin(); it != arc_map.end(); it ++){	
					//cost function fp, consider the oriented arcs
					if(!cmp_ip_addr(olsr,&(*it)->A_last_addr_,t_sr_addr_)
						&& !cmp_ip_addr(olsr,&(*it)->A_dest_addr_,&preHop)){
						(*it)->A_weight_ = OLSRCostFunctionFp(node,(*it)->A_weight_);
					}

					//cost function fe
					else if((!cmp_ip_addr(olsr,&(*it)->A_last_addr_,&preHop)
							&&cmp_ip_addr(olsr,&(*it)->A_dest_addr_,t_sr_addr_))
						||(!cmp_ip_addr(olsr,&(*it)->A_last_addr_,t_sr_addr_)
							&&cmp_ip_addr(olsr,&(*it)->A_dest_addr_,&preHop))){
						(*it)->A_weight_ = OLSRCostFunctionFe(node,(*it)->A_weight_);
					}
				}
			}
			*/

			addr_stack.push_back(*t_sr_addr_);	
			//node_t = node_map.find((*node_t).pre_addr_.v4).second;
			n_it = node_map.find((*node_t).pre_addr_.v4);
			node_t = (*n_it).second;
		} while(cmp_ip_addr(olsr, olsrSrc, &((*node_t).addr_ )));
		// wiss: bass yetla3 men el while ya3ni sar ma3na el tarafen taba3 el path l2aynehon bel node map...ma 3layna ella da5elon bel routing table

		//add itself
			//	olsr_ip_addr* t_sr_addr_; //= new olsr_ip_addr;
			//	t_sr_addr_ = *olsrSrc;
		addr_stack.push_back(*olsrSrc);

		//construct the routing entry
		int j = 0;
		while(addr_stack.empty() == false){
			olsr_ip_addr* temp_ip = new olsr_ip_addr;
			*temp_ip = addr_stack.back(); // wiss: este5raj el elements men el vector
			//(*m_rt_entry).addr_[j] = &addr_stack.back();
			(*m_rt_entry).addr_[j] = temp_ip;
			addr_stack.pop_back(); // wiss: mnem7i men el vector ba3ed ma n7etou bel routing table
			j++;
		}

		//it's better to verify the length of the route here. if j>MAZ_SR_LEN, the path should be discarded. 
		//to be finished


		if(DEBUG_OLSRV2){
			printf("\n");
			for (j = 0;j<MAX_SR_LEN; j++){
				
				printf("%x -->\t ",(*m_rt_entry).addr_[j]->v4);
				if ((*m_rt_entry).addr_[j]->v4 == (*olsrDest).v4)
					break;
			}
			printf("\n");
		}

		for (j = 0;j<MAX_SR_LEN; j++){
				if ((*m_rt_entry).addr_[j]->v4 == (*olsrDest).v4)
					break;
		}

		int numOfHops = j;

		//renew the cost of the arcs
		//type_flag defines the cost function to be used. 0 for no change, 1 for fp, 2 for fe
		int type_flag = 0;
		for(std::vector<Arc_map_tuple*>::iterator it = arc_map.begin(); it != arc_map.end(); it ++){
			olsr_ip_addr arc_start = (*it)->A_last_addr_;
			olsr_ip_addr arc_end = (*it)->A_dest_addr_;
						
			for(j=0;j<numOfHops;j++){
				olsr_ip_addr path_start = *((*m_rt_entry).addr_[j]);
				olsr_ip_addr path_end = *((*m_rt_entry).addr_[j+1]);
				if (((!cmp_ip_addr(olsr, &arc_start,&path_start))&&cmp_ip_addr(olsr,&arc_end,&path_end))
					 ||((!cmp_ip_addr(olsr,&path_start,&arc_end))&&cmp_ip_addr(olsr,&path_end,&arc_start))
					 ||((!cmp_ip_addr(olsr,&path_end,&arc_start))&&cmp_ip_addr(olsr,&path_start,&arc_end))
					 ||((!cmp_ip_addr(olsr,&path_end,&arc_end))&&cmp_ip_addr(olsr,&path_start,&arc_start))){
						type_flag = 2; //for cost function fe
				}else if(((!cmp_ip_addr(olsr,&arc_start,&path_start)&&!cmp_ip_addr(olsr,&arc_end,&path_end)))
						||((!cmp_ip_addr(olsr,&arc_start,&path_end)&&!cmp_ip_addr(olsr,&arc_end,&path_start)))){
						type_flag = 1; //for cost function fp
						break;
				}
			}
			if(type_flag == 1){
				(*it)->A_weight_ = OLSRCostFunctionFp(node,(*it)->A_weight_);
			}else if(type_flag ==2){
				(*it)->A_weight_ = OLSRCostFunctionFe(node,(*it)->A_weight_);
			}
			type_flag = 0;//reset the typeflag

		}

		(*m_rt_entry).dest = olsrDest;


		// add the entry to routing table
		add_rt_entry(olsr,m_rt_entry);


/*		m_rtable_t::iterator rt_it = lookup_route_entry(olsr,*olsrDest);

		if(DEBUG_OLSRV2){
		
			printf("\n");
			for (int i = 0;i<MAX_SR_LEN; i++){
				NodeAddress add_t = (*(rt_it->second->addr_[i])).v4;
				printf("* %x \t" ,add_t);
				if (add_t == (*olsrDest).v4){
					break;
				}
			}
		}*/			


	}

	//finish the route computation, set the flag
	set_flag(olsr, olsrDest->v4, false);
	
	
}


}

