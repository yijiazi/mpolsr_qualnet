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
#include <stdio.h>
#include <time.h>
#include <assert.h>

#include "mp_olsr_conf.h"

#include "mp_def.h"
#include "mp_olsr_debug.h"

#include "mp_olsr_util.h"
#include "mp_olsr_util_inline.h"

namespace MPOLSRv2{


//Functions Added for "olsr_niigata_ip_to_string(...)"

// PURPOSE :: Parses IPv4 address into a dotted-decimal string.
// PARAMETERS ::
// + ipAddress      : Olsr_u32_t   : IPv4 address to be converted into
//                                    the string.
// + addressString  : char*        : Storage for string.
// RETURN :: void
// NOTES        This function does not distinguish between network- and
//              host-byte order.

void ConvertIpv4AddressToString(
    olsr_u32_t ipAddress,
    char *addressString)
{
    sprintf(addressString, "%u.%u.%u.%u",
             ipAddress & 0xff,
             (ipAddress & 0xff00) >> 8,
             (ipAddress & 0xff0000) >> 16,
             (ipAddress & 0xff000000) >> 24);
}


//-----------------------------------------------------------------------------
// PURPOSE :: Parses IPv6 address into a dotted-decimal string.
// PARAMETERS ::
// + ipv6Address      : in6_addr_qualnet*     : Storage for ipv6address.
// + interfaceAddr    : char*         : Storage for ipv6address string
// RETURN :: None
//-----------------------------------------------------------------------------

void ConvertIpv6AddressToString(
        struct in6_addr_qualnet* ipv6Address,
        char* interfaceAddr,
        olsr_bool ipv4EmbeddeAddr)
{
    int noOfZero = 0;
    int counter = 0;
    char tempStr[32];
    int onceDoubleColon = 0;
    unsigned char* dummy = NULL;
    unsigned int dummyInt = 0;
    unsigned int prevDummyInt = 0;

    // Extra Error Checking.
    if (interfaceAddr == NULL)
    {
        olsr_printf("Error: - NULL interface Address\n");
    }
    interfaceAddr[0] = '\0';

    //Address is printed in following format.
    //1. The preferred form is x:x:x:x:x:x:x:x, where the 'x's are the
    //hexadecimal values of the eight 16-bit pieces of the address.
    //e.g. FEDC:BA98:7654:3210:FEDC:BA98:7654:3210
    //
    //2. In order to make writing addresses containing zero
    //bits easier a special syntax is available to compress the zeros.
    // The use of "::" indicates multiple groups of 16-bits of zeros.
    //  The "::" can only appear once in an address.
    //e.g. FF01:0:0:0:0:0:0:101  to FF01::101
    //
    //3. An alternative form that is sometimes more convenient when dealing
    //with a mixed environment of IPv4 and IPv6 nodes is
    //x:x:x:x:x:x:d.d.d.d, where the 'x's are the hexadecimal values of
    //the six high-order 16-bit pieces of the address, and the 'd's are
    //the decimal values of the four low-order 8-bit pieces of the
    //address (standard IPv4 representation).  Example:
    //0:0:0:0:0:0:13.1.68.3

    // Check for unsigned address.
    if (ipv6Address->s6_addr_32[0] == 0 &&
        ipv6Address->s6_addr_32[1] == 0 &&
        ipv6Address->s6_addr_32[2] == 0 &&
        ipv6Address->s6_addr_32[3] == 0)
    {
        sprintf(interfaceAddr,"::");
        return;
    }

    if (ipv6Address->s6_addr_32[0] == 0 &&
        ipv6Address->s6_addr_32[1] == 0 &&
        ipv6Address->s6_addr_8[8] == 0 &&
        ipv6Address->s6_addr_8[9] == 0)
    {
        if (ipv6Address->s6_addr_8[10] == 0 &&
            ipv6Address->s6_addr_8[11] == 0 &&
            ipv4EmbeddeAddr)
        {
            sprintf(tempStr,"::");
        }
        else
        {
            if (ipv4EmbeddeAddr ||
                (ipv6Address->s6_addr_8[10] == 0xff &&
                ipv6Address->s6_addr_8[11] == 0xff))
            {
                if (ipv6Address->s6_addr_8[10] == 0)
                {
                    sprintf(tempStr,"::%x:",ipv6Address->s6_addr_8[11]);
                }
                else
                {
                    dummyInt = ipv6Address->s6_addr_8[10] << 8;
                    dummyInt |=  ipv6Address->s6_addr_8[11];
                    sprintf(tempStr,"::%x:", dummyInt);
                }
            }
        }
        if (ipv4EmbeddeAddr ||
            (ipv6Address->s6_addr_8[10] == 0xff
            && ipv6Address->s6_addr_8[11] == 0xff))
        {

            strcat(interfaceAddr,tempStr);

            sprintf(tempStr,"%u.%u.%u.%u",
                (ipv6Address->s6_addr_32[3] & 0xff),
                (ipv6Address->s6_addr_32[3] & 0x0000ff00) >> 8,
                (ipv6Address->s6_addr_32[3] & 0x00ff0000) >> 16,
                 ipv6Address->s6_addr_32[3] >> 24);

            strcat(interfaceAddr,tempStr);

            return;
        }
    } // End of printing IPv6 Addresses with Embedded IPv4 Addresses

    counter = 0;
    noOfZero = 0;
    dummy = (unsigned char*)ipv6Address;
    while (counter < 16)
    {
        noOfZero = 0;
        while (counter < 16)
        {
            // Already '::' has been stuffed no need of stuffing other.
            if (onceDoubleColon == 1)
            {
                break;
            }
            dummyInt = dummy[counter];
            dummyInt = dummyInt << 8;
            dummyInt |= dummy[counter + 1];
            if (dummyInt == 0)
            {
                noOfZero++;
                prevDummyInt = dummyInt;
            }
            else
            {
                if (noOfZero > 1)
                {
                    strcat(interfaceAddr,"::");
                    noOfZero = 0;
                    onceDoubleColon = 1;
                }
                break;
            }
           counter += 2;
        }

        if (onceDoubleColon == 1)
        {
            dummyInt = dummy[counter];
            dummyInt = dummyInt << 8;
            dummyInt |= dummy[counter + 1];
        }
        if (noOfZero == 1)
        {
            sprintf(tempStr, "%x",prevDummyInt);
            if (strlen(interfaceAddr) > 0)
            {
                if (*(interfaceAddr + strlen(interfaceAddr) - 1) != ':')
                {
                    strcat(interfaceAddr,":");
                }
            }
            strcat(interfaceAddr,tempStr);
            prevDummyInt = 0;
        }
        sprintf(tempStr, "%x",dummyInt);
        if (strlen(interfaceAddr) > 0)
        {
            if (*(interfaceAddr + strlen(interfaceAddr) - 1) != ':')
            {
                strcat(interfaceAddr,":");
            }
        }
        strcat(interfaceAddr,tempStr);
        counter += 2;
    }
}


char *
olsr_niigata_ip_to_string(olsrv2 *olsr, union olsr_ip_addr *addr)
{
//WIN FIX: Needs to be resolved
  char *ret = NULL;
  olsrd_config* olsr_cnf = olsr->olsr_cnf;

  if(olsr_cnf->ip_version == AF_INET){
    //static char str1[INET_ADDRSTRLEN];
    //WIN FIX: Needs to be resolved
    //ret = (char *)inet_ntop(AF_INET, &addr->v4, str, sizeof(str));
    ret = (char*)olsr_malloc(INET_ADDRSTRLEN, __FUNCTION__);
    ConvertIpv4AddressToString( addr->v4, ret );
    //ret = str1;
  }
  else{
    /* IPv6 */
    //static char str2[INET6_ADDRSTRLEN];
    //WIN FIX: Needs to be resolved
    //ret = (char *)inet_ntop(AF_INET6, &addr->v6, str, sizeof(str));
    ret = (char*)olsr_malloc(INET6_ADDRSTRLEN, __FUNCTION__);
    ConvertIpv6AddressToString( &addr->v6, ret, OLSR_FALSE);

    //ret = str2;
  }

  return ret;
}


olsr_32_t cmp_ip_addr(struct olsrv2* olsr, const union olsr_ip_addr *x, const union olsr_ip_addr *y)
{
  if(olsr->olsr_cnf->ip_version == AF_INET)
    return !(x->v4 == y->v4);
  else
    return memcmp(x, y, sizeof(union olsr_ip_addr));
}

olsr_bool equal_netmask(struct olsrv2* olsr,
            const union hna_netmask *x,
            const union hna_netmask *y)
{
  if(olsr->olsr_cnf->ip_version == AF_INET)
    return (olsr_bool)(x->v4 == y->v4);

  else if(olsr->olsr_cnf->ip_version  == AF_INET6){
    return (olsr_bool)(x->v6 == y->v6);
  }

  else{
    olsr_error("Un known ip_version");
    assert(OLSR_FALSE);
  }
  return OLSR_FALSE;
}

void qualnet_print_clock_in_second(qualnet_time_t clock,
                   char stringInSecond[])
{
    char TimeString[4096];
    char TimeStringSecond[4096];
    char TimeStringNanoSecond[4096];
    int  LengthOfTimeString;

// Changed for Windows64
//#define ctoa(clock, string) sprintf(string, "%lld", clock)
#if defined (WIN32) || defined (_WIN32) || defined (__WIN64)
    #define ctoa(clock, string) sprintf(string, "%I64d", clock)
#else
    #define ctoa(clock, string) sprintf(string, "%lld", clock)
#endif

    ctoa(clock, TimeString);

    LengthOfTimeString = (int)strlen(TimeString);
    if (LengthOfTimeString <= 9) {
        strcpy(TimeStringSecond, "0");
        strncpy(TimeStringNanoSecond, "000000000", 9 - LengthOfTimeString);
        strncpy(&TimeStringNanoSecond[9-LengthOfTimeString],
            TimeString, LengthOfTimeString);
        TimeStringNanoSecond[9] = 0;
    }
    else {
        strncpy(TimeStringSecond, TimeString, LengthOfTimeString - 9);
        TimeStringSecond[LengthOfTimeString - 9] = 0;
        strncpy(TimeStringNanoSecond,
                &TimeString[LengthOfTimeString - 9],
                9);
        TimeStringNanoSecond[9] = 0;
    }

    sprintf(stringInSecond, "%s.%s", TimeStringSecond, TimeStringNanoSecond);
}

void get_current_time(struct olsrv2 *olsr, olsr_time_t *time)
{
  *time = olsr->current_sim_time;
}

void set_current_time(struct olsrv2 *olsr, olsr_time_t *time)
{
  *time = olsr->current_sim_time;
}

void update_time(olsr_time_t *time, olsr_32_t update)
{
  *time += (olsr_time_t)(update * OLSRv2_SECOND);
}

olsr_time_t olsr_max_time(olsr_time_t a, olsr_time_t b)
{
  if(a >= b)
    return a;
  else
    return b;
}

olsr_time_t olsr_min_time(olsr_time_t a, olsr_time_t b)
{
  if(a <= b)
    return a;
  else
    return b;
}


char* convert_to_char_from_time(time_t time)
{
  return asctime(localtime(&time));
}

L_STATUS get_neighbor_status(olsr_time_t *time,
                 olsr_time_t *N_SYM_time) {
  L_STATUS neighbor_status;

  if(olsr_cmp_time(*N_SYM_time, *time) < 0) {
    neighbor_status = LOST;
  }else {
    neighbor_status = SYMMETRIC;
  }

  return neighbor_status;
}

L_STATUS get_link_status(olsr_time_t time,
             olsr_time_t L_SYM_time,
             olsr_time_t L_ASYM_time,
             olsr_time_t L_LOST_LINK_time)
{
  L_STATUS link_status;


  if(olsr_cmp_time(L_LOST_LINK_time, time) >= 0)
    link_status = LOST;
  else{
    if(olsr_cmp_time(L_SYM_time, time) < 0 &&
       olsr_cmp_time(L_ASYM_time, time) < 0){
      link_status = LOST;

    }else if((olsr_cmp_time(L_SYM_time, time) >= 0 &&
          olsr_cmp_time(L_ASYM_time, time) < 0)
         || (olsr_cmp_time(L_SYM_time, time) >= 0 &&
         olsr_cmp_time(L_ASYM_time, time) >= 0)){
      link_status = SYMMETRIC;

    }else if(olsr_cmp_time(L_SYM_time, time) < 0 &&
         olsr_cmp_time(L_ASYM_time, time) >= 0){
      link_status = ASYMMETRIC;

    }else{
      link_status = UNSPEC;
    }
  }

  return link_status;
}

}
