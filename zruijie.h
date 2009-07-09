/*
 * =====================================================================================
 *
 *       Filename:  zdclient.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/06/2009 03:47:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
#include "md5.h"

#ifndef  ZRUIJIE_H
#define  ZRUIJIE_H


/* ZRuijie Version */
#define ZRJ_VER "0.1"

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
  u_int8_t  bit_value[4];
} BYTEArray;


void    send_eap_packet(enum EAPType send_type);
void    show_usage();
char*   get_md5_digest(const char* str, size_t len);
void    action_by_eap_type(enum EAPType pType, 
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const u_char *packet);
void    send_eap_packet(enum EAPType send_type);
void    init_frames();
void    init_info();
void    init_device();
void    init_arguments(int *argc, char ***argv);
int     set_device_new_ip();
void    fill_password_md5(u_char attach_key[], u_int id);
int     program_running_check();
void    daemon_init(void);
void    show_local_info();
void    print_server_info (const u_char *packet, u_int packetlength);
int     code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen);

void        set_frame_id (u_char *frame, u_char id);
uint32_t    ruijie_byte_to_host_val (const uint8_t *array);

void
ruijie_host_val_to_byte (uint8_t *to_array, uint32_t host_val);


void
get_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);

void* keep_alive(void *arg);
#endif   /* ----- #ifndef ZRUIJIE_INC  ----- */

