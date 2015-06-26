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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <iostream>
#include <list>
#include <map>
#include <vector>

#include <stdlib.h>

#include "mp_proc_m_rtable.h"
namespace MPOLSRv2{

/*
void proc_link_set(struct olsrv2 *olsr,
           union olsr_ip_addr *local_iface_addr,
           union olsr_ip_addr *source_addr,
           olsr_u8_t link_status,
           olsr_u8_t willingness,
           double validity_time,
           double interval_time)
{*/

void init_m_rtable(struct olsrv2 * olsr){
	olsr->m_rtable = new OLSR_M_RTABLE;
	olsr->pathCounter = 0;
	set_flag(olsr,true);
}

//set the flag for a dest node
void set_flag(struct olsrv2 *olsr,olsr_u32_t nodeId,bool flag){
	std::map<olsr_u32_t, bool>::iterator it;
//	olsr->change_link_set = olsr->change_two_neigh_set = OLSR_FALSE;
	OLSR_M_RTABLE *rtable = olsr->m_rtable;
	
	it = (*rtable).out_of_date.find(nodeId);

	if(it == (*rtable).out_of_date.end()){
		//there is no flag info in the rtable, add a new one
		(*rtable).out_of_date.insert(std::pair<olsr_u32_t,bool>(nodeId,flag));
		(*rtable).out_of_date[nodeId] = true;
	}else{
		//set the flag
		(*it).second = flag;
	}
}

//set flag for all the dest node
void set_flag(struct olsrv2 *olsr, bool flag){
	std::map<olsr_u32_t, bool>::iterator it;
	OLSR_M_RTABLE *rtable = olsr->m_rtable;

	olsr->pathCounter = 0;

	it = (*rtable).out_of_date.begin();

	for(it = (*rtable).out_of_date.begin(); it != (*rtable).out_of_date.end(); it ++){
		(*it).second = flag;
	}
}

bool get_flag(struct olsrv2 * olsr,olsr_u32_t nodeId){
	OLSR_M_RTABLE *rtable = olsr->m_rtable;

/*	if((*rtable).out_of_date[nodeId] == NULL){
		(*rtable).out_of_date.insert(std::pair<olsr_u32_t,bool>(nodeId,true));
		(*rtable).out_of_date[nodeId] = true;
	}*/

	std::map<olsr_u32_t,bool>::iterator it = (*rtable).out_of_date.find(nodeId);
	if(it == (*rtable).out_of_date.end()) {
		(*rtable).out_of_date.insert(std::pair<olsr_u32_t,bool>(nodeId,true));
		(*rtable).out_of_date[nodeId] = true;
	}

	return (*rtable).out_of_date[nodeId];
}

bool check_arc_tuple(std::vector<Arc_map_tuple*> *arc_map, Arc_map_tuple *arc_map_tuple){
	bool exist_flag = false;

	std::vector<Arc_map_tuple*>::iterator it;
	
	for(it = (*arc_map).begin();it != (*arc_map).end(); it++){
		if ((*it)->A_dest_addr_.v4 == (*arc_map_tuple).A_dest_addr_.v4 
				&& (*it)->A_last_addr_.v4 == (*arc_map_tuple).A_last_addr_.v4 )
		exist_flag = true;
	}
	return exist_flag;

}

void add_rt_entry(struct olsrv2 * olsr,OLSR_m_rt_entry *rt_entry){
	OLSR_M_RTABLE *rtable = olsr->m_rtable;
	
	olsr_ip_addr* dest = (*rt_entry).dest;
	(*rtable).m_rt.insert(std::pair<olsr_u32_t,OLSR_m_rt_entry *>((*dest).v4, rt_entry));
	//((*rtable).m_rt).erase((*dest).v4);
}

void rm_rt_entry(struct olsrv2 * olsr,union olsr_ip_addr dest_addr_){
	OLSR_M_RTABLE *rtable = olsr->m_rtable;
	(*rtable).m_rt.erase(dest_addr_.v4);
	
}

m_rtable_t::iterator lookup_route_entry(struct olsrv2 * olsr,union olsr_ip_addr dest_addr_){
	OLSR_M_RTABLE *rtable = olsr->m_rtable;
	return 	(*rtable).m_rt.find(dest_addr_.v4);
}
}
