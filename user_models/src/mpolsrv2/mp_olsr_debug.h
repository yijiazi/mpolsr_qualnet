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
#ifndef MPOLSR_DEBUG_OLSRV2_H
#define MPOLSR_DEBUG_OLSRV2_H

#include <stdio.h>
#include <stdlib.h>
/* for syslog */
#include <stdarg.h>

namespace MPOLSRv2{

#if defined (WIN32) || defined (_WIN32) || defined (__WIN64)

    //#include <varargs.h>
    #ifndef __func__
        #define __func__ __FUNCTION__
    #endif

    #define vsnprintf _vsnprintf

#else

    #include <syslog.h>

#endif

#define STDOUT stdout
#define STDERR stderr
#define DEF_LEVEL -1

/* for syslog */
#define OLSR_LOG_INFO   1
#define OLSR_LOG_WARNING 2
#define OLSR_LOG_ERROR  3

/* function prototype */

#if defined __cplusplus
//extern "C"
//{
#endif

  void init_olsr_debug(void);
  void set_output_level(int);
  void olsr_error(const char *, ...);

  void olsr_printf(const char *, ...);

#if defined __cplusplus
//}
#endif

/*#define olsr_debug(level,format,...)\
{} */

#define debug_code(x)   {}

extern int d_level;
void olsr_die(const char *, ...);


void set_debug_handler(char *);
void set_std_handler(char *);
int get_output_level();
FILE *get_debug_handler();

/* for syslog */
void olsr_openlog(const char *);
void olsr_syslog(int, char *, ...);
void olsr_closelog(void);
void olsr_shutdown(int);
}
#endif /* ifndef OLSR_DEBUG_OLSRV2_H */
