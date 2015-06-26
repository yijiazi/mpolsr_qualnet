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
#include "mp_olsr_multipath.h"
 namespace MPOLSRv2{
#ifndef _ADDON_MPOLSRv2_NIIGATA_
#define _ADDON_MPOLSRv2_NIIGATA_


//olsrv2_niigata

//qualnet
//#include "main.h"

#define OLSRv2_DEFAULT_HELLO_INTERVAL             (2 * SECOND) //(SECOND)
#define OLSRv2_DEFAULT_TC_INTERVAL                (5 * SECOND) //(SECOND)

#define OLSRv2_DEFAULT_REFRESH_TIMEOUT_INTERVAL   (2 * SECOND) //(SECOND)

#define OLSRv2_DEFAULT_MAX_HELLO_JITTER         (250 * MILLI_SECOND) //(MILLISECOND)
#define OLSRv2_DEFAULT_MAX_TC_JITTER            (250 * MILLI_SECOND) //(MILLISECOND)

#define OLSRv2_DEFAULT_MAX_FORWARD_JITTER       (250 * MILLI_SECOND)//(MILLISECOND)

#define OLSRv2_DEFAULT_START_HELLO             (1 * SECOND) //(SECOND)
#define OLSRv2_DEFAULT_START_TC                (1 * SECOND) //(SECOND)
#define OLSRv2_DEFAULT_START_REFRESH_TIMEOUT   (1 * SECOND) //(SECOND)

#define OLSRv2_DEFAULT_NEIGHBOR_HOLD_TIME      (3 * OLSRv2_DEFAULT_HELLO_INTERVAL) //(SECOND)
#define OLSRv2_DEFAULT_TOPOLOGY_HOLD_TIME      (3 * OLSRv2_DEFAULT_TC_INTERVAL) //(SECOND)
#define OLSRv2_DEFAULT_DUPLICATE_HOLD_TIME    (30 * SECOND) //(SECOND)

#define OLSRv2_DEFAULT_LINK_LAYER_NOTIFICATION  TRUE
#define OLSRv2_DEFAULT_PACKET_RESTORATION       FALSE
#define OLSRv2_DEFAULT_RESTORATION_TYPE         1 //1:Simple

#define OLSRv2_DEFAULT_NUMBER_OF_PATH 3
#define OLSRv2_DEFAULT_ROUTE_RECOVERY TRUE
#define OLSRv2_DEFAULT_COST_FpA 3.0      //cost function fp(n+1) = a*fp(n) + b
#define OLSRv2_DEFAULT_COST_FpB 0
#define OLSRv2_DEFAULT_COST_FeA 2.0    	//cost function fe(n+1) = a*fc(n) + b
#define OLSRv2_DEFAULT_COST_FeB 0
#define OLSRv2_DEFAULT_FEC FALSE     //for FEC coding
#define OLSRv2_DEFAULT_SYSTEMATIC FALSE
#define OLSRv2_DEFAULT_NO_OF_PACKETS_NEEDED_FOR_FEC 4
#define OLSRv2_DEFAULT_NO_OF_PROJECTION 4
#define OLSRv2_DEFAULT_NO_OF_PROJECTION_NEEDED 2
#define OLSRv2_DEFAULT_IP_SOURCE_ROUTING FALSE

/* Shift to olsr_conf.h for MAC mismatch
typedef enum
  {
    L_ENDIAN,
    B_ENDIAN
  }MACHINE_TYPE;
*/
void RoutingMPOLSRv2_Niigata_Init(Node *node,
                                const NodeInput *nodeInput,
                                int interfaceIndex,
                                NetworkType networkType);
void
RoutingMPOLSRv2_Niigata_AddInterface(Node *node,
                                   const NodeInput *nodeInput,
                                   int interfaceIndex,
                                   NetworkType networkType);
void RoutingMPOLSRv2_Niigata_Layer(Node *, Message *);
void RoutingMPOLSRv2_Niigata_Finalize(Node* , int);

// Function to handle data packets. Sometimes for incoming packets
// to update internal variables. Sometimes outgoing packets from nodes
// upperlayer or protocols
void OLSRRouterFunction(
         Node* node,
         Message* msg,
         NodeAddress destAddr,
         NodeAddress previousHopAddress,
         BOOL* packetWasRouted);

// to compute the multiple path
void OLSRRouteComputation(
		Node *node, 
		Message* msg, 
		NodeAddress srcAddr,
		NodeAddress destAddr);

int Get_queue_length(struct olsrv2 *olsr, union olsr_ip_addr *Node_add);  // codexxx

float Set_Weight(std::map<olsr_u32_t, Dijkstra_node*> node_map,union olsr_ip_addr *dest_add,union olsr_ip_addr *last_add); //codexxx



//read the source route info into the pack head
int OLSRSetSourceRoute(
		Node *node,
		Message* msg,
		m_rtable_t::iterator rt_it,
		NodeAddress destAddr,
		bool routeRecoveryFlag);

//get the next hop info from the packet
NodeAddress OLSRGetNextHopFromSR(
		Node *node,
		Message* msg,
		NodeAddress srcAddr,
		NodeAddress destAddr);

NodeAddress GetQualnetIPv4FromOLSR(Node* node,NodeAddress olsraddr);
NodeAddress GetOLSRFromQualnetIPv4(Node* node, NodeAddress qualnetaddr);




#endif
}
