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

#ifndef __OLSR_MULTIPATH_H
#define __OLSR_MULTIPATH_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <list>
#include <map>

#include <time.h>
//#include <main.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"

//#include "olsr.h"
namespace MPOLSRv2{


#define MAX_SR_LEN 32
#define MAX_NODE 1024
#define MAX_WEIGHT 65535
#define SIZE_OF_MULTIPATH_COMMON_HEAD 8

//using namespace std;

typedef struct OLSR_m_rt_entry{
	union olsr_ip_addr * dest;
	union olsr_ip_addr * addr_[MAX_SR_LEN];
} OLSR_m_rt_entry;

typedef std::multimap<olsr_u32_t,OLSR_m_rt_entry*> m_rtable_t;

typedef struct OLSR_m_rtable{
	m_rtable_t m_rt;
	std::map<olsr_u32_t,bool> out_of_date;
} OLSR_M_RTABLE;

typedef enum
{
	T_TYPE,
	P_TYPE,
}Dijkstra_node_type;


typedef struct Dijkstra_node{
	union olsr_ip_addr addr_;
	union olsr_ip_addr pre_addr_;
	float weight_;
	//node type
	Dijkstra_node_type node_type_;
	int QueueInByte ;
	
}Dijkstra_node;


//
typedef struct Arc_map_tuple{
	union olsr_ip_addr A_dest_addr_;
	union olsr_ip_addr A_last_addr_;
	olsr_u16_t A_seq_;
  	olsr_time_t A_time_;
	float A_weight_;
	float A_original_weight_;	
	
}Arc_map_tuple;
}

#endif

