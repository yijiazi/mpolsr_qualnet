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

#include "mp_mantissa.h"
#include "math.h"
#include "mp_olsr_protocol.h"
namespace MPOLSRv2{

/**
 *Function that converts a double to a mantissa/exponent
 *product as described in RFC3626:
 *
 * value = C*(1+a/16)*2^b [in seconds]
 *
 *  where a is the integer represented by the four highest bits of the
 *  field and b the integer represented by the four lowest bits of the
 *  field.
 *
 *@param interval the time interval to process
 *
 *@return a 8-bit mantissa/exponent product
 */

olsr_u8_t
double_to_me(double interval)
{
  int a, b;

  b = 0;

  while(interval / VTIME_SCALE_FACTOR >= pow((double)2, (double)b))
    b++;

  b--;
  if(b < 0)
    {
      a = 1;
      b = 0;
    }
  else
    if (b > 15)
      {
    a = 15;
    b = 15;
      }
    else
      {
    a = (int)(16*((double)interval/(VTIME_SCALE_FACTOR*(double)pow((double)2,b))-1));
    while(a >= 16)
      {
        a -= 16;
        b++;
      }
      }

  //printf("Generated mantissa/exponent(%d/%d): %d from %f\n", a, b, (olsr_u8_t) (a*16+b), interval);
  //printf("Resolves back to: %f\n", me_to_double((olsr_u8_t) (a*16+b)));
  return (olsr_u8_t) (a*16+b);
}




/**
 *Function that converts a mantissa/exponent 8bit value back
 *to double as described in RFC3626:
 *
 * value = C*(1+a/16)*2^b [in seconds]
 *
 *  where a is the integer represented by the four highest bits of the
 *  field and b the integer represented by the four lowest bits of the
 *  field.
 *
 *@param me the 8 bit mantissa/exponen value
 *
 *@return a double value
 */
double
me_to_double(olsr_u8_t me)
{
  int a, b;

  a = me>>4;
  b = me - a*16;

  return (double)(VTIME_SCALE_FACTOR*(1+(double)a/16)*(double)pow((double)2,b));
}
}
