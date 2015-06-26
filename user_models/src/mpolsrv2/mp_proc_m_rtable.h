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

#ifndef __MP_PROC_M_RTABLE_H
#define __MP_PROC_M_RTABLE_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <list>
#include <map>
#include <vector>

#include <time.h>
//#include <main.h>

#include "mp_olsr_types.h"
#include "mp_olsr_common.h"
#include "mp_olsr_list.h"
#include "mp_olsr_multipath.h"

#include "mp_olsr.h"
namespace MPOLSRv2{


//#define MAX_SR_LEN 16
#define MAX_NODE 1024

//using namespace std;
/*
typedef struct OLSR_m_rt_entry{
	union olsr_ip_addr * dest;
	union olsr_ip_addr * addr_[MAX_SR_LEN];
} OLSR_m_rt_entry;

typedef std::multimap<olsr_u32_t,OLSR_m_rt_entry> m_rtable_t;

typedef struct OLSR_m_rtable{
	m_rtable_t m_rt;
	std::map<olsr_u32_t,bool> out_of_date;
} OLSR_M_RTABLE;
*/
//void set_flag(struct olsrv2* olsr,olsr_u32_t nodeId, bool flag);

void init_m_rtable(struct olsrv2 *olsr);

void set_flag(struct olsrv2 *olsr,olsr_u32_t nodeId, bool flag);

void set_flag(struct olsrv2 *olsr, bool flag);

bool get_flag(struct olsrv2 *olsr, olsr_u32_t nodeId);

bool check_arc_tuple(std::vector<Arc_map_tuple*> *arc_map, Arc_map_tuple *arc_map_tuple);

void add_rt_entry(struct olsrv2 *olsr, OLSR_m_rt_entry *rt_entry);

void rm_rt_entry(struct olsrv2 *olsr, union olsr_ip_addr dest_addr_);

m_rtable_t::iterator lookup_route_entry(struct olsrv2 *olsr, union olsr_ip_addr dest_addr_);
}
#endif
