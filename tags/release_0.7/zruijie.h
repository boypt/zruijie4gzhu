/*
 * =====================================================================================
 *
 *       Filename:  zruijie.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/06/2009 10:28:21 PM
 *       Revision:  none
 *       Compiler:  gcc
 *       File Last Modify:$Date$
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */


#include	"commondef.h"

/* #####   FUNCTION DEFINITIONS  -  LOCAL TO THIS SOURCE FILE   ##################### */
/* zruijie.c内实现，在zruijie.c中调用的函数*/


static void 
action_by_eap_type(enum EAPType pType, 
                        const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet) ;

static enum EAPType 
get_eap_type(const struct eap_header *eap_header);

#ifndef __linux
static int bsd_get_mac(const char ifname[], uint8_t eth_addr[]);
#endif
