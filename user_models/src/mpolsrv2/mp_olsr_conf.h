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
#ifndef __MPOLSR_CONF_H
#define __MPOLSR_CONF_H

#include "mp_olsr_types.h"

#include "mp_olsr_protocol.h"


#include "mp_olsr_debug.h"
#include "mp_def.h"


#include "mp_olsr_list.h"
#include "mp_olsr_common.h"

namespace MPOLSRv2{

/* Default valuse not declared in olsr_protocol.h */
#define DEF_POLLRATE        0.05
#define DEF_WILL_AUTO       OLSR_TRUE
#define DEF_ALLOW_NO_INTS   OLSR_TRUE
#define DEF_TOS             16
#define DEF_DEBUG_OLSRV2LVL        1
#define DEF_IPC_CONNECTIONS 0
#define DEF_USE_HYST        OLSR_TRUE
#define DEF_LQ_LEVEL        0
#define DEF_LQ_WSIZE        10
#define DEF_CLEAR_SCREEN    OLSR_FALSE

/* Bounds */

#define MIN_INTERVAL        0.01

#define MAX_POLLRATE        10.0
#define MIN_POLLRATE        0.01
#define MAX_DEBUG_OLSRV2LVL        9
#define MIN_DEBUG_OLSRV2LVL        0
#define MAX_TOS             16
#define MIN_TOS             0
#define MAX_WILLINGNESS     7
#define MIN_WILLINGNESS     1
#define MAX_MPR_COVERAGE    20
#define MIN_MPR_COVERAGE    1
#define MAX_TC_REDUNDANCY   2
#define MIN_TC_REDUNDANCY   0
#define MAX_HYST_PARAM      1.0
#define MIN_HYST_PARAM      0.0
#define MAX_LQ_LEVEL        2
#define MIN_LQ_LEVEL        0
#define MAX_LQ_WSIZE        128
#define MIN_LQ_WSIZE        3

#ifndef IPV6_ADDR_SITELOCAL
#define IPV6_ADDR_SITELOCAL    0x0040U
#endif

typedef enum
{
  NOTMATCH = 0,
  DEBUG_OLSRV2LEVEL = 1,
  IPVERSION,
  ALLOWNOINT,
  TOSVALUE,
  WILLNESS,
  MAXCONNECTIONS,
  HOST,
  NET,
  MASK,
  USEHYST,
  SCALING,
  THRHIGH,
  THRLOW,
  LQLEVEL,
  LQWINDOWSIZE,
  POLLRATE,
  TCREDUNDANCY,
  MPRCOVERAGE,
  IFACE,
  IPV4BROADCAST,
  IPV6ADDRTYPE,
  IPV6MULTICASTSITE,
  IPV6MULTICASTGLOBAL,
  HELLOINTERVAL,
  HELLOVALIDITY,
  TCINTERVAL,
  TCVALIDITY,
  MAINTERVAL,
  MAVALIDITY,
  WEIGHT,
  ATTACHEDNETWORK,
  ATTACHEDNETWORK6
} olsr_conf;

//Shifted from routing_olsrv2_niigata.h
typedef enum
  {
    L_ENDIAN,
    B_ENDIAN
  }MACHINE_TYPE;


struct olsr_msg_params
{
  float emission_interval;
  float validity_time;
};

struct olsr_lq_mult
{
  union olsr_ip_addr addr;
  float val;
  struct olsr_lq_mult *next;
};

struct olsr_if_weight
{
  int value;
  olsr_bool fixed;
};

struct if_config_options
{
  union olsr_ip_addr ipv4_broadcast;
  int ipv6_addrtype;
  union olsr_ip_addr ipv6_multi_site;
  union olsr_ip_addr ipv6_multi_glbl;
  struct olsr_if_weight weight;
  struct olsr_msg_params hello_params;
  struct olsr_msg_params tc_params;
  struct olsr_msg_params ma_params;

  struct olsr_lq_mult *lq_mult;
};



struct olsr_if
{
  char *name;
  char *config;
  int index;
  olsr_bool configured;
//struct interface *interf;
  struct if_config_options *cnf;
  struct olsr_if *next;
};

struct hyst_param
{
  float scaling;
  float thr_high;
  float thr_low;
};


struct ipc_host
{
  union olsr_ip_addr host;
  struct ipc_host *next;
};

struct ipc_net
{
  union olsr_ip_addr net;
  union olsr_ip_addr mask;
  struct ipc_net *next;
};


typedef struct attached_network
{
  union olsr_ip_addr network_addr;
  union olsr_ip_addr netmask;
  olsr_u8_t prefix_length;
  struct attached_network *next;
}ATTACHED_NETWORK;

/*
 * The config struct
 */

struct olsrd_config
{
  int debug_level;
  olsr_bool no_fork;
  int ip_version;
  size_t ipsize;
  olsr_bool allow_no_interfaces;
  olsr_u16_t tos;
  olsr_bool willingness_auto;
  olsr_u8_t willingness;
  int ipc_connections;
  olsr_bool open_ipc;
  olsr_bool use_hysteresis;
  struct hyst_param hysteresis_param;
  float pollrate;
  olsr_u8_t tc_redundancy;
  olsr_u8_t mpr_coverage;
  olsr_bool clear_screen;
  olsr_u8_t lq_level;       /* link_quality */
  olsr_u32_t lq_wsize;
  struct plugin_entry *plugins;
  struct ipc_host *ipc_hosts;
  struct ipc_net *ipc_nets;

  //WIN FIX: Need to resolve this
  //struct olsr_if *interfaces;

  olsr_u32_t     interfaceNum;
  olsr_u16_t ifcnt;
  ATTACHED_NETWORK *attached_net_addr;
  ATTACHED_NETWORK *attached_net_addr6;
  olsr_u32_t       advNetAddrNum;
  olsr_u32_t       advNetAddrNum6;

};

//for qualnet
typedef struct olsrv2_qualnet_config
{
   olsr_64_t hello_interval;
   olsr_64_t tc_interval;
   olsr_64_t timeout_interval;
   olsr_64_t max_hello_jitter;
   olsr_64_t max_tc_jitter;
   olsr_64_t max_forward_jitter;
   olsr_64_t start_hello;
   olsr_64_t start_tc;
   olsr_64_t start_timeout;
   olsr_64_t neighbor_hold_time;
   olsr_64_t topology_hold_time;
   olsr_64_t duplicate_hold_time;
   olsr_bool link_layer_notification;
   olsr_bool packet_restoration;
   int restoration_type;
   int 	number_of_path;
   olsr_bool route_recovery;
   olsr_bool ip_source_routing;
   float cost_fp_a;
   float cost_fp_b;
   float cost_fe_a;
   float cost_fe_b;
   olsr_bool fec;
   olsr_bool fec_systemmatic;
   int No_of_packets_needed_for_fec;
   int No_of_projection;
   int No_of_proection_needed;
} OLSRv2QualConf;

#define     IPV4_MODE       (olsr_cnf->ip_version == AF_INET)
#define     IP_LEN          (IPV4_MODE ? 4 : 16)

#if defined __cplusplus
//extern "C"
//{
#endif

/*
 * Interface to parser
 */

  void usage();

  struct olsrd_config *olsrd_parse_cnf(const char *);

  void parsing_config_file(struct olsrd_config *, FILE *);
  void parse_check_config(struct olsrd_config* );

  olsr_conf olsrd_matching(const char *);

  int olsrd_sanity_check_cnf(struct olsrd_config *);

  struct olsrd_config *get_default_cnf(void);

  void set_default_cnf(struct olsrd_config *);

  int set_default_ifcnfs(struct olsr_if *, struct if_config_options *);

  struct if_config_options *get_default_if_config(void);

  void olsrd_free_cnf(struct olsrd_config *);

  void olsrd_print_cnf(struct olsrd_config *);

  int olsrd_write_cnf(struct olsrd_config *, const char *);

  int olsrd_write_cnf_buf(struct olsrd_config *, char *, olsr_u32_t);

  void GetIpAddr(struct olsrv2* olsr, union olsr_ip_addr* addr, char* str);
#if defined __cplusplus
//}
#endif

//Shifted from routing_olsrv2_niigata.cpp
MACHINE_TYPE GetMachineType(void);
}

#endif
