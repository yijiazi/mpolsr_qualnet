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

#include "mp_olsr_debug.h"
#include "mp_olsr.h"
#include <string.h>
namespace MPOLSRv2{

#define DEBUG_OLSRV2_HANDLER "olsr.log"
#define STD_HANDLER   "olsr.log"

/* static value */
static FILE *debug_handler;
static FILE *std_handler;
static int def_output_level;

/* static function prototype */
static void init_handler(void);
static void init_output_level(void);

/* function definitions */

#ifndef NOSTDOUT
/* when use a program error ex. fopen etc */
void olsr_error(const char *format,...){
  va_list arglist;
  int rtn,rtn_log;

  char tmp_buf[128];

  va_start(arglist,format);

  // output format into tmp_buf
  rtn = vsnprintf(tmp_buf, sizeof(tmp_buf) -1 ,format,arglist);

  // output system error message
  perror(tmp_buf);

  // print olsr_error messege into file
  rtn_log = vfprintf(debug_handler, format, arglist);

  va_end(arglist);

  exit(1);
  return;
}

void olsr_printf(const char *format,...){
  va_list arglist;
  int rtn;

  if( std_handler == NULL )
    olsr_die("Please excute init_olsr_debug()\n");

  /* output string to std_handler */
  va_start(arglist,format);
  rtn = vfprintf(std_handler,format,arglist);
  va_end(arglist);

  return;
}

#endif /* ifndef NOSTDOUT */

/* when use a flag error ex. flag = -1 */
void olsr_die(const char *format,...){
  va_list arglist;
  int rtn;

  va_start(arglist,format);
  rtn = vfprintf(STDERR,format,arglist);

  exit(1);

  return;
}

/* initialize handler ,std & err output level */
void init_olsr_debug(){
    if(std_handler == NULL)
    {
    init_handler();
    //init_output_level();
    }

  return;
}

/* this is static function ,called init_olsr_debug() */
void init_handler(){
  debug_handler = STDERR;
  std_handler  = STDOUT;

  // kakima changed
  set_debug_handler(DEBUG_OLSRV2_HANDLER);
  set_std_handler(STD_HANDLER);

  // original
  //set_debug_handler("/tmp/olsr.log");
  return;
}

/* this is static function ,called init_olsr_debug() */
void init_output_level(void){
  def_output_level = DEF_LEVEL;

  return;
}

/* change default value(def_output_level) */
void set_output_level(int level){
  def_output_level = level;

  return;
}

/* change output from stderr to anything */
void set_debug_handler(char *handler){

  if( (std_handler = fopen(handler,"w")) == NULL)
    olsr_error("fopen()");

  return;
}

/* change output from stdout to anything */
void set_std_handler(char *handler){

  if( (std_handler = fopen(handler,"w")) == NULL)
    olsr_error("fopen()");

  return;
}


/* for syslog */
//WIN FIX: syslog is not required for windows
#if !defined (WIN32) && !defined (_WIN32) && !defined (__WIN64)
void olsr_openlog(const char *ident){
  openlog(ident, LOG_PID ,LOG_DAEMON);
  setlogmask(LOG_UPTO(LOG_INFO));

  return;
}


void olsr_syslog(int level,char *format,...){
  int log_level;
  va_list arglist;

  switch(level){
  case OLSR_LOG_INFO:
    log_level = LOG_INFO;
     break;
  case OLSR_LOG_WARNING:
    log_level = LOG_WARNING;
    break;
  case OLSR_LOG_ERROR:
    log_level = LOG_ERR;
    break;
  default:
    return;
  }

  va_start(arglist,format);
  vsyslog(log_level,format,arglist);
  va_end(arglist);

  return;
}

/* Basically, not needed */
void olsr_closelog(void){
  closelog();

  return;
}
#endif
int get_output_level()
{
  return def_output_level;
}

FILE *get_debug_handler()
{
  return debug_handler;
}

void olsr_shutdown(int signum){
  //finalize_qualnet_olsrv2_niigata();
  exit(1);
}
}
