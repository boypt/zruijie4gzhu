/*
 * =====================================================================================
 *
 *       Filename:  eap_protocol.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/07/2009 02:55:00 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */

#include	"eap_protocol.h"
//#include	"zruijie.h"
#include	"blog.h"
#include	"md5.h"
#include	<pthread.h>
#include    <unistd.h>

static char*   
get_md5_digest(const char* str, size_t len);
static void 
fill_password_md5(uint8_t attach_key[], uint8_t eap_id);
static void*   
keep_alive(void *arg);

/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文缓冲区，由init_frame函数初始化。
 *-----------------------------------------------------------------------------*/
uint8_t             eapol_start[1000];            /* EAPOL START报文 */
uint8_t             eapol_logoff[1000];           /* EAPOL LogOff报文 */
uint8_t             eap_response_ident[1000]; /* EAP RESPON/IDENTITY报文 */
uint8_t             eap_response_md5ch[1000]; /* EAP RESPON/MD5 报文 */
uint8_t             eap_life_keeping[45];
uint32_t            ruijie_live_serial_num;
uint32_t            ruijie_succes_key;
extern enum STATE   state;
extern pcap_t       *handle;

void
action_eapol_success(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    extern enum STATE   state;
    extern int          background;
    extern pthread_t    live_keeper_id;

    state = ONLINE;
    fprintf(stdout, ">>Protocol: EAP_SUCCESS\n");
    fprintf(stdout, "&&Info: Authorized Access to Network. \n");
    print_server_info (packet, packetinfo->caplen, EAP_SUCCESS);

    /* 成为后台守护进程 */
    if (background){
        background = 0;         /* 防止以后误触发 */
        daemon_init();
    }
    /* 获得succes_key */
    ruijie_succes_key = ntohl (
            ruijie_byte_to_int32 (
                (const uint8_t*)(packet + 0x104)));

    /* 打开保持线程 */
    if ( !live_keeper_id ) {
        if ( pthread_create(&live_keeper_id, NULL, 
                    keep_alive, NULL) != 0 ){
            fprintf(stderr, "@@Fatal ERROR: "
                            "Init Life Keeper Thread Failure.\n");
            exit (EXIT_FAILURE);
        }
    }
}

void
action_eapol_failre(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    extern int          background;
    extern int          exit_flag;
    extern pthread_t    exit_waiter_id;

    state = READY;
    fprintf(stdout, ">>Protocol: EAP_FAILURE\n");
    if(state == ONLINE){
        fprintf(stdout, "&&Info: SERVER Forced Logoff\n");
    }
    if (state == STARTED){
        fprintf(stdout, "&&Info: Invalid Username or Client info mismatch.\n");
    }
    if (state == ID_AUTHED){
        fprintf(stdout, "&&Info: Invalid Password.\n");
    }
    print_server_info (packet, packetinfo->caplen, EAP_FAILURE);
    if (exit_flag) {
        fprintf(stdout, "&&Info: Session Ended.\n");
        pcap_breakloop (handle);
    }
    else{
        exit_flag = 1;
        if (pthread_create (&exit_waiter_id, NULL,
                    thread_wait_exit, NULL) != 0) {
            fprintf(stderr, "@@Fatal ERROR: Thread failure.\n");
            exit (EXIT_FAILURE);
        }
    }
}

void
action_eap_req_idnty(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    extern int          exit_flag;

    if (state == STARTED){
        fprintf(stdout, ">>Protocol: REQUEST EAP-Identity\n");
    }
    if (exit_flag)
        return;
    eap_response_ident[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_IDENTITY);
}

void
action_eap_req_md5_chg(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    state = ID_AUTHED;

    fprintf(stdout, ">>Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
    fill_password_md5((uint8_t*)eap_head->eap_md5_challenge, eap_head->eap_id);
    eap_response_md5ch[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
}

void* 
keep_alive(void *arg)
{
    while (1) {
        ruijie_int32_to_byte (eap_life_keeping + 0x18, 
                                htonl (ruijie_live_serial_num + ruijie_succes_key));

        ruijie_int32_to_byte (eap_life_keeping + 0x22, 
                                htonl (ruijie_live_serial_num));
        ++ruijie_live_serial_num;
        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
        sleep (30);
    }
    return (void*)0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  send_eap_packet
 *  Description:  根据eap类型发送相应数据包
 * =====================================================================================
 */
void 
send_eap_packet(enum EAPType send_type)
{
    uint8_t         *frame_data;
    int             frame_length = 0;

    switch(send_type){
        case EAPOL_START:
            state = STARTED;
            frame_data= eapol_start;
            frame_length = 1000;
            fprintf(stdout, ">>Protocol: SEND EAPOL-Start\n");
            break;
        case EAPOL_LOGOFF:
            state = READY;
            frame_data = eapol_logoff;
            frame_length = 1000;
            fprintf(stdout, ">>Protocol: SEND EAPOL-Logoff\n");
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 1000;
            fprintf(stdout, ">>Protocol: SEND EAP-Response/Identity\n");
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 1000;
            fprintf(stdout, ">>Protocol: SEND EAP-Response/Md5-Challenge\n");
            break;
        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
            frame_data = eap_life_keeping;
            frame_length = 45;
            fprintf(stdout, ">>Protocol: SEND EAPOL_KEEP_ALIVE\n");
            break;
        default:
            fprintf(stderr,"&&IMPORTANT: Wrong Send Request Type.%02x\n", send_type);
            return;
    }
    if (pcap_sendpacket(handle, frame_data, frame_length) != 0)
    {
        fprintf(stderr,"&&IMPORTANT: Error Sending the packet: %s\n", 
                                                    pcap_geterr(handle));
        return;
    }
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_password_md5
 *  Description:  给RESPONSE_MD5_Challenge报文填充相应的MD5值。
 *  只会在接受到REQUEST_MD5_Challenge报文之后才进行，因为需要
 *  其中的Key
 * =====================================================================================
 */
void 
fill_password_md5(uint8_t attach_key[], uint8_t eap_id)
{
    extern char *password;
    extern int  password_length;
    char *psw_key = malloc(1 + password_length + 16);
    char *md5_challenge_key;
    psw_key[0] = eap_id;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    md5_challenge_key = get_md5_digest(psw_key, 1 + password_length + 16);
    memcpy (eap_response_md5ch + 14 + 10, md5_challenge_key, 16);

    free (psw_key);
    free (md5_challenge_key);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_md5_digest
 *  Description:  calcuate for md5 digest
 * =====================================================================================
 */
char* 
get_md5_digest(const char* str, size_t len)
{
	md5_state_t state;
	md5_byte_t digest[16];
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    char *result = malloc(16);
    memcpy(result, digest, 16);
    return result;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  print_server_info
 *  Description:  提取中文信息并打印输出
 * =====================================================================================
 */
void 
print_server_info (const uint8_t *packet, u_int packetlength,
                    enum EAPType pack_type)
{
    char            msg_buf[1024];
    size_t          msg_len;
    size_t          buf_len = 1024;
    iconv_t         cd;
    char            *outbuf = msg_buf;
    char            *inbuf;

    cd = iconv_open("utf-8", "gb2312");
    if (cd == 0) 
        goto ENDS;

    if (pack_type == RUIJIE_EAPOL_MSG)
        goto RUIJIE_MSG;

    /* success和failure报文系统信息的固定位置 */
    msg_len = ntohs(*(uint16_t*)(packet + 0x1a));
    if (msg_len < 3)
        goto ENDS;
    inbuf = (char*)(packet + 0x1c);
    memset (msg_buf, 0, buf_len);
    if (iconv (cd, &inbuf, &msg_len,
                        &outbuf, &buf_len) == -1) 
       goto ENDS;
    fprintf (stderr, ">>Server Message: %s\n", msg_buf);

    if (packetlength < 0x110)
        goto ENDS;

    /* success报文关于用户账户信息的位置 */
    msg_len = *(uint8_t*)(packet + 0x114);
    inbuf = (char*)(packet + 0x115);
    memset (msg_buf, 0, buf_len);
    if (iconv (cd, &inbuf, &msg_len, 
                        &outbuf, &buf_len) == -1) 
       goto ENDS;
    fprintf (stderr, ">>Account Info: %s\n", msg_buf);
    goto ENDS;
    
    /* 锐捷的通知报文 */
RUIJIE_MSG:;
    inbuf = (char*)(packet + 0x1b);
    msg_len = strlen (inbuf);
    memset (msg_buf, 0, buf_len);
    if (iconv (cd, &inbuf, &msg_len, 
                        &outbuf, &buf_len) == -1) 
       goto ENDS;
    fprintf (stderr, ">>Manager Notification: %s\n", msg_buf);

ENDS:;
    iconv_close (cd);
    return;
}


