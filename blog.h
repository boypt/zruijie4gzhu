/*
 * =====================================================================================
 *
 *       Filename:  blog.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/06/2009 06:24:17 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *       
 *       本文件算法和数据修改自MyStar，原作者为netxray@byhh，
 *       保留原函数命名规则。 Alog，Blog算法函数已由BOYPT重写。
 * =====================================================================================
 */



#ifndef BLOG_H
#define BLOG_H

/* The Blog algorithm is mainly de-assembled out by SnowWings.        */
/* We should thank him very much, because the algorithm is crucial.  */

#include	"commondef.h"

uint8_t
Alog(uint8_t val);

void
Blog(uint8_t *RuijieExtra);

uint32_t
ruijie_byte_to_int32 (const uint8_t *array);

void
ruijie_int32_to_byte (uint8_t *to_array, uint32_t host_val);

#endif
