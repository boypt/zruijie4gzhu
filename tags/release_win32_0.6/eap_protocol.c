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
#include 	<assert.h>
#include	"eap_protocol.h"
//#include	"zruijie.h"
#include	"blog.h"
#include	"md5.h"

static char*   
get_md5_digest(const char* str, size_t len);
static void 
fill_password_md5(uint8_t attach_key[], uint8_t eap_id);
DWORD WINAPI keep_alive();
DWORD WINAPI wait_exit();

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
    extern HANDLE       hLIFE_KEEP_THREAD;

    state = ONLINE;

    /* 获得succes_key */
    ruijie_succes_key = get_ruijie_success_key (packet);
    print_server_info (packet);

    /* 打开保持线程 */
    hLIFE_KEEP_THREAD = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)keep_alive, 0, 0, 0);
}

void
action_eapol_failre(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
	extern HANDLE		hEXIT_WAITER;
	extern HANDLE		hLIFE_KEEP_THREAD;

    print_server_info (packet);

	if (state == ONLINE || state == LOGOFF) {
		state = READY;
		DWORD code = 0;
		GetExitCodeThread (hLIFE_KEEP_THREAD, &code);
		if (code == STILL_ACTIVE) {
			TerminateThread (hLIFE_KEEP_THREAD, 0);
            WaitForSingleObject (hLIFE_KEEP_THREAD, 1000);
		}
		
		code = 0;
		GetExitCodeThread (hEXIT_WAITER, &code);
		if (code == STILL_ACTIVE) {
			TerminateThread (hEXIT_WAITER, 0);
            WaitForSingleObject (hEXIT_WAITER, 1000);
		}

		pcap_breakloop (handle);
	}
	else if (state == CONNECTING) {
		state = LOGOFF;
		hEXIT_WAITER = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)wait_exit, 0, 0, 0);
		/* show server info */
	}
}

void
action_eap_req_idnty(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
    if (state == LOGOFF)
        return;
	state = CONNECTING;
    eap_response_ident[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_IDENTITY);
}

void
action_eap_req_md5_chg(const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet)
{
	state = CONNECTING;
    fill_password_md5((uint8_t*)eap_head->eap_md5_challenge, eap_head->eap_id);
    eap_response_md5ch[0x13] = eap_head->eap_id;
    send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
}

DWORD WINAPI keep_alive()
{
    while (1) {
        ruijie_int32_to_byte (eap_life_keeping + 0x18, 
                                htonl (ruijie_live_serial_num + ruijie_succes_key));

        ruijie_int32_to_byte (eap_life_keeping + 0x22, 
                                htonl (ruijie_live_serial_num));
        ++ruijie_live_serial_num;
        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
        Sleep (30000);
    }
	return 0;
}

DWORD WINAPI wait_exit()
{
    int 	i = 10;
	char	msg[10];
    do {
		snprintf (msg, sizeof(msg), "wait.. %d", i);
		update_interface_state(msg);
		printf("%d\n", i);
        Sleep (1000);
    }while (i--);
	state = READY;
    pcap_breakloop (handle);
	return 0;
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
            frame_data= eapol_start;
            frame_length = 1000;
            break;
        case EAPOL_LOGOFF:
            frame_data = eapol_logoff;
            frame_length = 1000;
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 1000;
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 1000;
            break;
        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE:
            frame_data = eap_life_keeping;
            frame_length = 45;
            break;
        default:
            return;
    }
    pcap_sendpacket(handle, frame_data, frame_length);
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
    extern char password[];
    extern int  password_length;
    char *psw_key; 
    char *md5;

    psw_key = malloc(1 + password_length + 16);
    psw_key[0] = eap_id;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    md5 = get_md5_digest(psw_key, 1 + password_length + 16);
    memcpy (eap_response_md5ch + 14 + 10, md5, 16);

    free (psw_key);
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
    static md5_byte_t digest[16];
	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    return (char*)digest;
}

uint32_t
get_ruijie_success_key (const uint8_t *success_packet)
{
    uint16_t        msg_length;
    uint16_t        empty_length;
    uint16_t        key_offset;
    
    msg_length = ntohs(*(uint16_t*)(success_packet + 0x1a));
    empty_length = ntohs(*(uint16_t*)(success_packet + 0x1c + msg_length + 0x04));

//    printf ("%02x...%02x...", msg_length, empty_length);

    key_offset = 0x1c + msg_length + 0x06 + empty_length + 0x12;

    return ntohl (ruijie_byte_to_int32 (success_packet + key_offset));
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  print_server_info
 *  Description:  提取中文信息并打印输出
 * =====================================================================================
 */
void 
print_server_info (const uint8_t *packet)
{
    char            msg_buf[1024];
    char            *msg;
    uint16_t        msg_length;
    uint16_t        empty_length;
    uint16_t        account_info_offset;

    msg_length = ntohs(*(uint16_t*)(packet + 0x1a));
    empty_length = ntohs(*(uint16_t*)(packet + 0x1c + msg_length + 0x04));
    account_info_offset = 0x1c + msg_length + 0x06 + empty_length + 0x12 + 0x09;

    /* success和failure报文系统信息的固定位置 */
    if (msg_length) {
        msg = (char*)(packet + 0x1c);
		memset (msg_buf, 0, 1024);
		snprintf (msg_buf, msg_length + 1, "%s\n", msg);
		edit_info_append (msg_buf);
    }

    /* success报文关于用户账户信息 */
    if (0x1a48 == ntohs(*(uint16_t*)(packet + account_info_offset))) {
        msg_length = *(uint8_t*)(packet + account_info_offset + 0x07);
        msg = (char*)(packet + account_info_offset + 0x08);
		memset (msg_buf, 0, 1024);
		snprintf (msg_buf, msg_length + 1, "%s\n", msg);
		edit_info_append (msg_buf);
    }
}

void
print_notification_msg(const uint8_t *packet)
{
    char            msg_buf[1024] = {0};
    size_t          msg_length;
    char            *msg;

    /* 锐捷的通知报文 */
    msg = (char*)(packet + 0x1b);
    msg_length = strlen (msg);

	snprintf (msg_buf, msg_length + 1, "%s\n", msg);
	edit_info_append (msg_buf);
}


