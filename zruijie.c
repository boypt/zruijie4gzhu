/*
 * =====================================================================================
 *
 *       Filename:  zruijie.c
 *
 *    Description:  
 *
 *        Version:  0.1
 *        Created:  07/06/2009 08:07:12 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */


#include    "zruijie.h"
#include	"blog.h"
//#include <assert.h>
#include    <pthread.h>
#include    <unistd.h>

char        errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
pcap_t      *handle;			   /* packet capture handle */

/* #####   TYPE DEFINITIONS  -   ######################### */
/*-----------------------------------------------------------------------------
 *  用户信息的赋值变量，由init_argument函数初始化
 *-----------------------------------------------------------------------------*/
int         dhcp_on = 0;               /* DHCP 模式标记 */
int         background = 0;            /* 后台运行标记  */
int         exit_flag = 0;
char        *dev = NULL;               /* 连接的设备名 */
char        *username = NULL;          
char        *password = NULL;
int         username_length;
int         password_length;
char        *user_gateway = NULL;      /* 由用户设定的四个报文参数 */
char        *user_dns = NULL;
char        *user_ip = NULL;
char        *user_mask = NULL;
char        *client_ver = NULL;         /* 报文协议版本号 */

/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文相关信息变量，由init_info函数初始化。
 *-----------------------------------------------------------------------------*/
bpf_u_int32 local_ip;			       /* 网卡IP，网络序，下同 */
bpf_u_int32 local_mask;			       /* subnet mask */
bpf_u_int32 local_gateway = -1;
bpf_u_int32 local_dns = -1;
uint8_t     local_mac[ETHER_ADDR_LEN]; /* MAC地址 */

uint8_t     client_ver_val[2];

uint8_t     muticast_mac[] =            /* Star认证服务器多播地址 */
                        {0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03};

uint32_t    live_serial_num;
uint32_t    succes_key;


/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文缓冲区，由init_frame函数初始化。
 *-----------------------------------------------------------------------------*/
uint8_t      eapol_start[1000];            /* EAPOL START报文 */
uint8_t      eapol_logoff[1000];           /* EAPOL LogOff报文 */
uint8_t      eap_response_ident[1000]; /* EAP RESPON/IDENTITY报文 */
uint8_t      eap_response_md5ch[1000]; /* EAP RESPON/MD5 报文 */
uint8_t      eap_life_keeping[45];
enum STATE  state;                     /* program state */
pthread_t   live_keeper_id;
/* #####   TYPE DEFINITIONS   ######################### */

// debug function
void 
print_hex(const uint8_t *array, int count)
{
    int i;
    for(i = 0; i < count; i++){
        if ( !(i % 16))
            printf ("\n");
        printf("%02x ", array[i]);
    }
    printf("\n");
}

void
show_usage()
{
    printf( "\n"
            "zRuijie for GZHU %s \n"
            "\t  -- Client for Ruijie Authentication in GZHU campus.\n"
            "\n"
            "  Usage:\n"
            "\tRun under root privilege, usually by `sudo', with your \n"
            "\taccount info in arguments:\n\n"
            "\t-u, --username        Your username.\n"
            "\t-p, --password        Your password.\n\n"
            "\tUse `--dhcp' if you're GZHU user. \n"
            "\n"
            "  Optional Arguments:\n\n"
            "\t-g, --gateway         Specify Gateway server address. \n\n"

            "\t-d, --dns             Specify DNS server address. \n\n"

            "\t--dhcp                Set DHCP mode.\n"
            "\t                      You may need to run `dhclient' manualy to\n"
            "\t                      renew your IP address. \n\n"

            "\t--device              Specify which device to use.\n"
            "\t                      Default is usually eth0.\n\n"

            "\t--ip                  With DHCP mode on, program need to send \n"
            "\t--mask                packet to the server with IP/MASK info, use \n"
            "\t                      this arguments to specify them, or program will\n"
            "\t                      use a pseudo one. \n"
            "\t                      Affacts only when both promopted.\n\n"

            "\t-b, --background      Program fork as daemon after authentication.\n\n"

            "\t--ver                 Specify a client version. \n"
            "\t                      Default is `3.50'.\n\n"

            "\t-l                    Tell the process to Logoff.\n\n"

            "\t-h, --help            Show this help.\n\n"
            "\n"
            "  About zRuijie:\n\n"
            "\tzRuijie is a program developed individually and release under MIT\n"
            "\tlicense as free software, with NO any relaiontship with Ruijie company.\n\n\n"
            
            "\tAnother PT work. Blog: http://apt-blog.co.cc\n"
            "\t\t\t\t\t\t\t\t2009.07.05\n",
            ZRJ_VER);
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
 *         Name:  get_eap_type
 *  Description:  根据报文的动作位返回enum EAPType内定义的报文类型
 * =====================================================================================
 */
enum EAPType 
get_eap_type(const struct eap_header *eap_header) 
{
    switch (eap_header->eap_t){
        case 0x01:
            if ( eap_header->eap_op == 0x01 &&
                        eap_header->eap_id == 0x03 )
                return EAP_REQUEST_IDENTITY_KEEP_ALIVE;
            if ( eap_header->eap_op == 0x01)
                return EAP_REQUEST_IDENTITY;
            if ( eap_header->eap_op == 0x04)
                return EAP_REQUETS_MD5_CHALLENGE;

            break;
        case 0x03:
        //    if (eap_header->eap_id == 0x02)
            return EAP_SUCCESS;
            break;
        case 0x04:
            return EAP_FAILURE;
    }
    fprintf (stderr, "&&IMPORTANT: Unknown Package : eap_t:      %02x\n"
                    "                               eap_id: %02x\n"
                    "                               eap_op:     %02x\n", 
                    eap_header->eap_t, eap_header->eap_id,
                    eap_header->eap_op);
    return ERROR;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  action_by_eap_type
 *  Description:  根据eap报文的类型完成相关的应答
 * =====================================================================================
 */
void 
action_by_eap_type(enum EAPType pType, 
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet) {
//    printf("PackType: %d\n", pType);
    switch(pType){
        case EAP_SUCCESS:
            state = ONLINE;
            fprintf(stdout, ">>Protocol: EAP_SUCCESS\n");
            fprintf(stdout, "&&Info: Authorized Access to Network. \n");
//            print_server_info (packet, packetinfo->caplen);
            
            /* 成为后台守护进程 */
            if (background){
                background = 0;         /* 防止以后误触发 */
                daemon_init();
            }
            /* 获得succes_key */
            succes_key = ruijie_byte_to_host_val ((const uint8_t *)(packet + 0x104));
//            print_hex (packet + 0x104, 4);

            /* 打开保持线程 */
            if ( !live_keeper_id ) {
                if ( pthread_create(&live_keeper_id, NULL, 
                                            keep_alive, NULL) != 0 ){
                    fprintf(stderr, "@@Fatal ERROR: Init Live keep thread failure.\n");
                    exit (EXIT_FAILURE);
                }
            }

            break;
        case EAP_FAILURE:
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
//            print_server_info (packet, packetinfo->caplen);
            pcap_breakloop (handle);
            break;
        case EAP_REQUEST_IDENTITY:
            if (state == STARTED){
                fprintf(stdout, ">>Protocol: REQUEST EAP-Identity\n");
            }
            set_frame_id (eap_response_ident, header->eap_id);
            send_eap_packet(EAP_RESPONSE_IDENTITY);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            state = ID_AUTHED;
            fprintf(stdout, ">>Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
            fill_password_md5((uint8_t*)header->eap_md5_challenge, header->eap_id);
            send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
            break;
        case EAP_REQUEST_IDENTITY_KEEP_ALIVE:

            break;
        default:
            return;
    }
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
    uint8_t *frame_data;
    int     frame_length = 0;
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

            fprintf(stdout, ">>Protocol: SEND EAP_RESPONSE_IDENTITY_KEEP_ALIVE\n");
            break;
        default:
            fprintf(stderr,"&&IMPORTANT: Wrong Send Request Type.%02x\n", send_type);
            return;
    }
    if (pcap_sendpacket(handle, frame_data, frame_length) != 0)
    {
        fprintf(stderr,"&&IMPORTANT: Error Sending the packet: %s\n", pcap_geterr(handle));
        return;
    }
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_packet
 *  Description:  pcap的回呼函数，当收到EAPOL报文时自动被调用
 * =====================================================================================
 */
void
get_packet(uint8_t *args, const struct pcap_pkthdr *header, 
    const uint8_t *packet)
{
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */
    const struct eap_header *eap_header;

    ethernet = (struct ether_header*)(packet);
    eap_header = (struct eap_header *)(packet + SIZE_ETHERNET);

    enum EAPType p_type = get_eap_type(eap_header);
    action_by_eap_type(p_type, eap_header, header, packet);
    return;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_frames
 *  Description:  初始化发送帧的数据
 * =====================================================================================
 */
void 
init_frames()
{
    int data_index;

    //Ruijie OEM Extra （V2.56）  by soar
    uint8_t RuijieExtra[144] = {
    // OEM Extra
    // 0 --> 22
      0xff,0xff,0x37,0x77, // Encode( 0x00,0x00,0x13,0x11 )
                           // 求反并头尾颠倒.add by lsyer
      0xff,                // Encode( 0x01/00  EnableDHCP flag )
                           // 0xff:Static IP  0x3f:DHCP
      0x00,0x00,0x00,0x00, // Encode( IP )
      0x00,0x00,0x00,0x00, // Encode( SubNetMask )
      0x00,0x00,0x00,0x00, // Encode( NetGate )
      0x00,0x00,0x00,0x00, // Encode( DNS )
      0x00,0x00,           // Checksum( )
    // 23 --> 58
    // ASCII 8021x.exe
      0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,
    // 59 --> 77
      0x00,0x00,0x00,0x00, // 8021x.exe File Version (2.56.00)
                           // base16 code.add by lsyer
      0x00,                // unknow flag
      // Const strings
      0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,
      // 78 --> 118
      // 32bits spc. Random strings
      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
      // 32bits spc. Random strings
      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
      // Const strings
      0x00,0x00,0x13,0x11,0x18,0x06,0x00,0x00,0x00,
      // 119
      0x00,               // DHCP and first time flag
      // V2.56 (and upper?) added
      // 120 -->
      0x1A,0x0E,0x00,0x00,0x13,0x11,0x2D,0x08,  // Const strings
      // 128 --> 141
      0x00,0x00,0x00,0x00,0x00,0x00,            // True NIC MAC
      0x1A,0x08,0x00,0x00,0x13,0x11,0x2F,0x02   // Const strings
    };

    RuijieExtra[0x3B] = client_ver_val[0];
    RuijieExtra[0x3C] = client_ver_val[1];
    if (dhcp_on)
        RuijieExtra[0x04] = 0x7f;

    /*****  EAPOL Header  *******/
    uint8_t eapol_eth_header[SIZE_ETHERNET];
    struct ether_header *eth = (struct ether_header *)eapol_eth_header;
    memcpy (eth->ether_dhost, muticast_mac, 6);
    memcpy (eth->ether_shost, local_mac, 6);
    eth->ether_type =  htons (0x888e);

    InitializeBlog (local_ip, local_mask, local_gateway, local_dns, dhcp_on);
    FillNetParamater (RuijieExtra + 5);

    
    /**** EAPol START ****/
    uint8_t start_data[4] = {0x01, 0x01, 0x00, 0x00};
    memset (eapol_start, 0, 1000);
    memcpy (eapol_start, eapol_eth_header, 14);
    memcpy (eapol_start + 14, start_data, 4);
    memcpy (eapol_start + 18, RuijieExtra, sizeof(RuijieExtra));

    /****EAPol LOGOFF ****/
    uint8_t logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
    memset (eapol_logoff, 0, 1000);
    memcpy (eapol_logoff, eapol_eth_header, 14);
    memcpy (eapol_logoff + 14, logoff_data, 4);
    memcpy (eapol_logoff + 18, RuijieExtra, sizeof(RuijieExtra));


    /* EAP RESPONSE IDENTITY */
    uint8_t eap_resp_iden_head[9] = {0x01, 0x00, 
                                    0x00, 5 + username_length,  /* eapol_length */
                                    0x02, 0x01, 
                                    0x00, 5 + username_length,       /* eap_length */
                                    0x01};
    
    data_index = 0;
    memcpy (eap_response_ident + data_index, eapol_eth_header, 14);
    data_index += 14;
    memcpy (eap_response_ident + data_index, eap_resp_iden_head, 9);
    data_index += 9;
    memcpy (eap_response_ident + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_ident + data_index, RuijieExtra, sizeof(RuijieExtra));

//    print_hex (eap_response_ident, 14 + 9 + username_length + 46);

    /** EAP RESPONSE MD5 Challenge **/
    uint8_t eap_resp_md5_head[10] = {0x01, 0x00, 
                                   0x00, 6 + 16 + username_length, /* eapol-length */
                                   0x02, 0x02, 
                                   0x00, 6 + 16 + username_length, /* eap-length */
                                   0x04, 0x10};

    data_index = 0;
    memcpy (eap_response_md5ch + data_index, eapol_eth_header, 14);
    data_index += 14;
    memcpy (eap_response_md5ch + data_index, eap_resp_md5_head, 10);
    data_index += 26;// 剩余16位在收到REQ/MD5报文后由fill_password_md5填充 
    memcpy (eap_response_md5ch + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_md5ch + data_index, RuijieExtra, sizeof(RuijieExtra));

//    print_hex (eap_response_md5ch, 14 + 4 + 6 + 16 + username_length + 46);

    memcpy (eap_life_keeping, eapol_eth_header, 14);
    uint8_t ruijie_life_keep[] = {0x01,0xBF, 0x00,0x1E,
    0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,
    0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF};
    memcpy (eap_life_keeping + 14, ruijie_life_keep, 31);
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
fill_password_md5(uint8_t attach_key[], u_int eap_id)
{
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

void* keep_alive(void *arg)
{
//    printf ("succes_key: %08x\n", succes_key);

    while (1) {
        ruijie_host_val_to_byte (eap_life_keeping + 0x18, 
                                (live_serial_num + succes_key));

//        printf ("live+scu: %08x\n", live_serial_num + succes_key);

        ruijie_host_val_to_byte (eap_life_keeping + 0x22, 
                                live_serial_num);

//        printf ("live: %08x\n", live_serial_num);
        ++live_serial_num;
        send_eap_packet (EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
        sleep (30);
    }
}

void
set_frame_id (uint8_t *frame, uint8_t id) {
    frame[19] = id;
}

uint32_t
ruijie_byte_to_host_val (const uint8_t *array) 
{
    BYTEArray val;
    int i;
    for (i = 0; i < 4; ++i) {
        val.bit_value[i] = Alog (*(array + i));
    }
    return ntohl (val.int_value);
}

void
ruijie_host_val_to_byte (uint8_t *to_array, uint32_t host_val)
{
    BYTEArray val;
    val.int_value = htonl (host_val);
    int i;
    for (i = 0; i < 4; ++i) {
        to_array[i] = Alog (val.bit_value[i]);
    }
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_info
 *  Description:  初始化本地信息。
 *  涉及的全局变量：
 *  username            用户名
 *  password            用户密码
 *  username_length     用户名长度
 *  password_length     用户密码长度
 *  local_ip            本机IP
 *  local_mask          本机掩码
 *  local_gateway       网关地址
 *  local_dns           DNS地址
 *  client_ver          客户端版本
 * =====================================================================================
 */
void init_info()
{
    if(username == NULL || password == NULL){
        fprintf (stderr,"Error: NO Username or Password promoted.\n"
                        "Try zdclient --help for usage.\n");
        exit(EXIT_FAILURE);
    }
    username_length = strlen(username);
    password_length = strlen(password);

    if (user_ip)
        local_ip = inet_addr (user_ip);
    else 
        local_ip = 0;

    if (user_mask)
        local_mask = inet_addr (user_mask);
    else 
        local_mask = 0;

    if (user_gateway)
        local_gateway = inet_addr (user_gateway);
    else 
        local_gateway = 0;

    if (user_dns)
        local_dns = inet_addr (user_dns);
    else
        local_dns = 0;

    if (local_ip == -1 || local_mask == -1 || local_gateway == -1 || local_dns == -1) {
        fprintf (stderr,"ERROR: One of specified IP, MASK, Gateway and DNS address\n"
                        "in the arguments format error.\n");
        exit(EXIT_FAILURE);
    }

    if(client_ver == NULL)
        client_ver = "3.50";
    else{
        if (strlen (client_ver) > 4) {
            fprintf (stderr, "Error: Specified client version `%s' longer than 4 Bytes.\n"
                    "Try `zdclient --help' for more information.\n", client_ver);
            exit(EXIT_FAILURE);
        }
    }
    sscanf(client_ver, "%u.%u", (unsigned int *)client_ver_val, 
                                (unsigned int *)(client_ver_val + 1));

    live_serial_num = 0x0000102b;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_device
 *  Description:  初始化设备。主要是找到打开网卡、获取网卡MAC、IP，
 *  同时设置pcap的初始化工作句柄。
 * =====================================================================================
 */
void init_device()
{
    struct  bpf_program fp;			/* compiled filter program (expression) */
    char    filter_exp[51];         /* filter expression [3] */
    int     use_pseudo_ip = 0;      /* DHCP模式网卡无IP情况下使用伪IP的标志 */

    if(dev == NULL)
	    dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
			errbuf);
		exit(EXIT_FAILURE);
    }
	
	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

    /* get device basic infomation */
    struct ifreq ifr;
    int sock;
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    strcpy(ifr.ifr_name, dev);

    //获得网卡Mac
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    
    //尝试获得网卡IP
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        //获取不了IP
        if (dhcp_on){ //DHCP模式下
            use_pseudo_ip = 1; //设置标签
            fprintf(stdout, "&&Info: No IP attached to %s, use `169.254.216.45' instead.\n",
                    dev);
        }
        else {
            perror("ioctl");
            exit(EXIT_FAILURE);
        }
    }

    //如果用户同时指定了IP和MASK，则优先使用(已在init_info转换完成)，
    //否则由程序处理
    if (!(local_ip && local_mask)) {

        //获取不了IP，且用户没有定义IP，使用伪IP
        if (use_pseudo_ip) {
            local_ip = inet_addr ("169.254.216.45");
            local_mask = inet_addr ("255.255.255.0");
        }

        //获取到IP，使用网卡的真实IP
        else {
            local_ip = ((struct  sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

            //获得子网掩码
            if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
            {
                perror("ioctl");
                exit(EXIT_FAILURE);
            }
            local_mask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;
        }
    }


    /* construct the filter string */
    sprintf(filter_exp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"
                        " and ether proto 0x888e", 
                        local_mac[0], local_mac[1],
                        local_mac[2], local_mac[3],
                        local_mac[4], local_mac[5]);

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
    pcap_freecode(&fp);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  set_device_new_ip
 *  Description:  用于DHCP模式下，当成功验证后并收到服务器发来的保鲜报文，
 *  调用本函数重新获取本机IP并写入应答报文中。
 * =====================================================================================
 */
int set_device_new_ip()
{
    struct ifreq ifr;
    int sock;
    
    strcpy(ifr.ifr_name, dev);
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        return -1;
    }
    if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        return -1;
    }
    local_ip = ((struct  sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    local_mask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;

    size_t data_index = 14 + 9 + username_length + 1;
    memcpy (eap_response_ident + data_index, &local_ip, 4);
    data_index += 4;
    memcpy (eap_response_ident + data_index, &local_mask, 4);
    return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  code_convert
 *  Description:  字符串编码转换
 * =====================================================================================
 */
int 
code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    iconv_t cd;

    cd = iconv_open(to_charset,from_charset);

    if (cd==0) 
      return -1;
    memset(outbuf,0,outlen);

    if (iconv (cd, &inbuf, &inlen, &outbuf, &outlen)==-1) 
      return -1;
    iconv_close(cd);
    return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  print_server_info
 *  Description:  提取中文信息并打印输出
 * =====================================================================================
 */

void 
print_server_info (const uint8_t *packet, u_int packetlength)
{
    const uint8_t *str;
    
    {
        if ( *(packet + 0x2A) == 0x12) {
            str = (packet + 0x2B);
            goto FOUND_STR;
        }
        if (packetlength < 0x42)
            return;
        if ( *(packet + 0x42) == 0x12) {
            str = (packet + 0x43);
            goto FOUND_STR;
        }
        if (packetlength < 0x9A)
            return;
        if ( *(packet + 0x9A) == 0x12) {
            str = (packet + 0x9B);
            goto FOUND_STR;
        }
        if (packetlength < 0x120)
            return;
        if ( *(packet + 0x120) == 0x12) {
            str = (packet + 0x121);
            goto FOUND_STR;
        }
        return;
    }

    FOUND_STR:;

    char info_str [1024] = {0};
    code_convert ("gb2312", "utf-8", (char*)(str + 1), *str, info_str, 1024);
    fprintf (stdout, ">>Server Info: %s\n", info_str);
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  show_local_info
 *  Description:  显示信息
 * =====================================================================================
 */
void show_local_info ()
{
    printf("##### zRuijie for GZHU ver. %s ######\n", ZRJ_VER);
    printf("Device:     %s\n", dev);
    printf("MAC:        %02x:%02x:%02x:%02x:%02x:%02x\n",
                        local_mac[0],local_mac[1],local_mac[2],
                        local_mac[3],local_mac[4],local_mac[5]);
    printf("IP:         %s\n", inet_ntoa(*(struct in_addr*)&local_ip));
    printf("MASK:       %s\n", inet_ntoa(*(struct in_addr*)&local_mask));
    printf("Gateway:    %s\n", inet_ntoa(*(struct in_addr*)&local_gateway));
    printf("DNS:        %s\n", inet_ntoa(*(struct in_addr*)&local_dns));
    printf("Client ver: %s\n", client_ver);
    printf("######################################\n");
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_arguments
 *  Description:  初始化和解释命令行的字符串。getopt_long
 * =====================================================================================
 */
void init_arguments(int *argc, char ***argv)
{
    /* Option struct for progrm run arguments */
    static struct option long_options[] =
        {
        {"help",        no_argument,        0,              'h'},
        {"background",  no_argument,        &background,    1},
        {"dhcp",        no_argument,        &dhcp_on,       1},
        {"device",      required_argument,  0,              2},
        {"ver",         required_argument,  0,              3},
        {"username",    required_argument,  0,              'u'},
        {"password",    required_argument,  0,              'p'},
        {"ip",          required_argument,  0,              4},
        {"mask",        required_argument,  0,              5},
        {"gateway",     required_argument,  0,              'g'},
        {"dns",         required_argument,  0,              'd'},
        {0, 0, 0, 0}
        };
    int c;
    while (1) {

        /* getopt_long stores the option index here. */
        int option_index = 0;
        c = getopt_long ((*argc), (*argv), "u:p:g:d:hbl",
                        long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 0:
               break;
            case 'b':
                background = 1;
                break;
            case 2:
                dev = optarg;
                break;
            case 3:
                client_ver = optarg;
                break;
            case 4:
                user_ip = optarg;
                break;
            case 5:
                user_mask = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'g':
                user_gateway = optarg;
                break;
            case 'd':
                user_dns = optarg;
                break;
            case 'l':
                exit_flag = 1;
                break;
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case '?':
                if (optopt == 'u' || optopt == 'p'|| optopt == 'g'|| optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                fprintf (stderr,"Unknown option character `\\x%x'.\n", c);
                exit(EXIT_FAILURE);
        }
    }    
}


