/*
 * =====================================================================================
 *
 *       Filename:  commondef.h
 *
 *    Description:  common struct and fuction definitions.
 *
 *        Version:  1.0
 *        Created:  07/07/2009 02:38:17 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */


#ifndef  COMMONDEF_INC
#define  COMMONDEF_INC

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <getopt.h>
#include <iconv.h>

/* ZRuijie Version */
#define ZRJ_VER "0.3"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

struct eap_header {
    u_char eapol_v;
    u_char eapol_t;
    u_short eapol_length;
    u_char eap_t;
    u_char eap_id;
    u_short eap_length;
    u_char eap_op;
    u_char eap_v_length;
    u_char eap_md5_challenge[16];
};

enum EAPType {
    EAPOL_START,
    EAPOL_LOGOFF,
    EAP_REQUEST_IDENTITY,
    EAP_RESPONSE_IDENTITY,
    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
    EAP_REQUETS_MD5_CHALLENGE,
    EAP_RESPONSE_MD5_CHALLENGE,
    EAP_SUCCESS,
    EAP_FAILURE,
    RUIJIE_EAPOL_MSG,
    ERROR
};

enum STATE {
   READY,
   STARTED,
   ID_AUTHED,
   ONLINE
};

typedef union
{
  u_int32_t int_value;
  u_int8_t  byte_value[4];
} BYTEArray;


/* #####   FUNCTION DEFINITIONS  -  EXPORTED FUNCTIONS   ############################ */
/* main.c内实现的函数, 在zruijie.c调用*/
void    daemon_init(void);
void*   thread_wait_exit (void *arg);

/* #####   FUNCTION DEFINITIONS  -  EXPORTED FUNCTIONS   ############################ */
/* zruijie.c内实现，调用的函数*/
void    init_frames();
void    init_info();
void    init_device();
void    show_local_info();
void    get_packet(u_char *args, const struct pcap_pkthdr *header, 
                        const u_char *packet);
void    print_hex(const uint8_t *array, int count);
#endif   /* ----- #ifndef COMMONDEF_INC  ----- */


