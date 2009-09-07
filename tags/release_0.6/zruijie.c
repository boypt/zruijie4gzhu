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
#include	"eap_protocol.h"
#include    <assert.h>


/* #####   GLOBLE VAR DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  程序的主控制变量
 *-----------------------------------------------------------------------------*/
char        errbuf[PCAP_ERRBUF_SIZE];   /* error buffer */
pcap_t      *handle;			        /* packet capture handle */
enum STATE  state;                      /* program state */
pthread_t   live_keeper_id;             /*保鲜报文线程id*/
pthread_t   exit_waiter_id;
uint8_t     muticast_mac[] =            /* Star认证服务器多播地址 */
                        {0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03};

/* #####   GLOBLE VAR DEFINITIONS   ###################
 *-----------------------------------------------------------------------------
 *  用户信息的赋值变量，由init_argument函数初始化
 *-----------------------------------------------------------------------------*/
int         dhcp_on = 0;               /* DHCP 模式标记 */
int         background = 0;            /* 后台运行标记  */
int         exit_flag = 0;
char        *dev = NULL;               /* 连接的设备名 */
char        *username = NULL;          
char        *password = NULL;
char        *user_gateway = NULL;      /* 由用户设定的四个报文参数 */
char        *user_dns = NULL;           /* 字符串内保存点分ip格式ASCII */
char        *user_ip = NULL;
char        *user_mask = NULL;
char        *client_ver = NULL;         /* 报文协议版本号 */

/* #####   GLOBLE VAR DEFINITIONS   ######################### 
 *-----------------------------------------------------------------------------
 *  报文相关信息变量，由init_info 、init_device函数初始化。
 *-----------------------------------------------------------------------------*/
int         username_length;
int         password_length;
uint32_t    local_ip;			       /* 网卡IP，网络序，下同 */
uint32_t    local_mask;			       /* subnet mask */
uint32_t    local_gateway = -1;
uint32_t    local_dns = -1;
uint8_t     local_mac[ETHER_ADDR_LEN]; /* MAC地址 */
uint8_t     client_ver_val[2];
char        devname[64];


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

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_packet
 *  Description:  pcap的回呼函数，当收到EAPOL报文时自动被调用
 * =====================================================================================
 */
void
get_packet(uint8_t *args, const struct pcap_pkthdr *pcaket_header, 
    const uint8_t *packet)
{
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */
    const struct eap_header *eap_header;
    enum EAPType p_type;

    ethernet = (struct ether_header*)(packet);
    eap_header = (struct eap_header *)(packet + SIZE_ETHERNET);

    p_type = get_eap_type(eap_header);
    if (p_type != ERROR)
        action_by_eap_type(p_type, eap_header, pcaket_header, packet);
    return;
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
        case 0x00:
            if ( eap_header->eap_op == 0x1c &&
                        eap_header->eap_id == 0x00)
                return RUIJIE_EAPOL_MSG;
            break;
        case 0x01:
            if ( eap_header->eap_op == 0x01)
                return EAP_REQUEST_IDENTITY;
            if ( eap_header->eap_op == 0x04)
                return EAP_REQUETS_MD5_CHALLENGE;
            break;
        case 0x03:
            return EAP_SUCCESS;
            break;
        case 0x04:
            return EAP_FAILURE;
    }
    fprintf (stderr, "&&IMPORTANT: Unknown Package : eap_t :    %02x\n"
                     "                               eap_id:    %02x\n"
                     "                               eap_op:    %02x\n", 
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
                        const struct eap_header *eap_head,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet) {
//    printf("PackType: %d\n", pType);
    switch(pType){
        case EAP_SUCCESS:
            action_eapol_success (eap_head, packetinfo, packet);
            break;
        case EAP_FAILURE:
            action_eapol_failre (eap_head, packetinfo, packet);
            break;
        case EAP_REQUEST_IDENTITY:
            action_eap_req_idnty (eap_head, packetinfo, packet);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            action_eap_req_md5_chg (eap_head, packetinfo, packet);
            break;
        case RUIJIE_EAPOL_MSG:
            print_notification_msg (packet);
            break;
        default:
            return;
    }
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_info
 *  Description:  初始化本地信息。（字符串->二进制数值）
 * =====================================================================================
 */
void init_info()
{
    extern uint32_t  ruijie_live_serial_num;
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

    /* 默认3.50版本 */
    if(client_ver == NULL) {
//        client_ver = "3.50";
        client_ver_val[0] = 3;
        client_ver_val[1] = 50;
    }
    else{
        if (strlen (client_ver) > 4) {
            fprintf (stderr, "Error: Specified version `%s' longer than 4 Bytes.\n"
                    "Version format should be like `3.50'.\n"
                    "Try `zdclient --help' for more information.\n", client_ver);
            exit(EXIT_FAILURE);
        }
        sscanf(client_ver, "%u.%u", (unsigned int *)client_ver_val, 
                            (unsigned int *)(client_ver_val + 1));
    }

    ruijie_live_serial_num = 0x0000102b;
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
    struct          bpf_program fp;			/* compiled filter program (expression) */
    char            filter_exp[51];         /* filter expression [3] */
    pcap_if_t       *alldevs;
//    pcap_addr_t     *addrs;

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

    /* 使用第一块设备 */
    if(dev == NULL) {
        pcap_if_t *d;
        for (d = alldevs; d; d = d->next) {
            
            if (d->flags & PCAP_IF_LOOPBACK)
                continue;

            pcap_addr_t *a;
            char flag = 0;
            for(a = d->addresses; a; a=a->next) {

                if (flag) break;
                /* Get IP ADDR and MASK */
                if (a->addr->sa_family == AF_INET) {
                    local_ip = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
                    local_mask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
                    dev = d->name;
                    flag = 1;
                }
            }
        }

        strcpy (devname, dev);
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
    pcap_freealldevs(alldevs);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_frames
 *  Description:  初始化发送帧的数据缓冲区
 * =====================================================================================
 */
void 
init_frames()
{
    extern uint8_t      eapol_start[];        /* EAPOL START报文 */
    extern uint8_t      eapol_logoff[];       /* EAPOL LogOff报文 */
    extern uint8_t      eap_response_ident[]; /* EAP RESPON/IDENTITY报文 */
    extern uint8_t      eap_response_md5ch[]; /* EAP RESPON/MD5 报文 */
    extern uint8_t      eap_life_keeping[];   /* EAPOL KEEP ALIVE*/
//    uint8_t             circle_sum[2];
    int                 data_index;

    //Ruijie OEM Extra （V2.56）  by soar
//    uint8_t RuijieExtra[144] = {
//    // OEM Extra
//    // 0 --> 22
//      0xff,0xff,0x37,0x77, // Encode( 0x00,0x00,0x13,0x11 )
//                           // 求反并头尾颠倒.add by lsyer
//      0xff,                // Encode( 0x01/00  EnableDHCP flag )
//                           // 0xff:Static IP  0x3f:DHCP
//      0x00,0x00,0x00,0x00, // Encode( IP )
//      0x00,0x00,0x00,0x00, // Encode( SubNetMask )
//      0x00,0x00,0x00,0x00, // Encode( NetGate )
//      0x00,0x00,0x00,0x00, // Encode( DNS )
//      0x00,0x00,           // Checksum( )
//    // 23 --> 58
//    // ASCII 8021x.exe
//      0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,
//      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
//      0x00,0x00,0x00,0x00,
//    // 59 --> 77
//      0x00,0x00,0x00,0x00, // 8021x.exe File Version (2.56.00)
//                           // base16 code.add by lsyer
//      0x00,                // unknow flag <-!!!! //0x03
//      // Const strings
//      0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,
//      // 78 --> 118
//      // 32bits spc. Random strings
//      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
//      // 32bits spc. Random strings
//      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
//      // Const strings
//      0x00,0x00,0x13,0x11,0x18,0x06,0x00,0x00,0x00,
//      // 119
//      0x00,               // DHCP and first time flag
//      // V2.56 (and upper?) added
//      // 120 -->
//      0x1A,0x0E,0x00,0x00,0x13,0x11,0x2D,0x08,  // Const strings
//      // 128 --> 141
//      0x00,0x00,0x00,0x00,0x00,0x00,            // True NIC MAC
//      0x1A,0x08,0x00,0x00,0x13,0x11,0x2F,0x02   // Const strings
//    };


    uint8_t RuijieExtra[] = {
0xff, 0xff, 0x37, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, 0x31, 0x78, 
0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x32, 0x00, 0x02, 0x00, 
0x00, 0x00, 0x13, 0x11, 0x01, 0x33, 0x1a, 0x28, 0x00, 0x00, 0x13, 0x11, 0x17, 0x22, 0x30, 0x31, 
0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x1a, 0x0c, 
0x00, 0x00, 0x13, 0x11, 0x18, 0x06, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x0e, 0x00, 0x00, 0x13, 0x11, 
0x2d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x08, 0x00, 0x00, 0x13, 0x11, 0x2f, 0x02, 
0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x35, 0x03, 0x00, 0x1a, 0x18, 0x00, 0x00, 0x13, 0x11, 0x36, 
0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x1a, 0x18, 0x00, 0x00, 0x13, 0x11, 0x38, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x88, 0x00, 0x00, 0x13, 0x11, 0x4d, 
0x82, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 
0x3f, 0x40, 0x41, 0x42, 0x34, 0x31, 0x61, 0x36, 0x32, 0x32, 0x35, 0x39, 0x33, 0x32, 0x61, 0x61, 
0x66, 0x36, 0x37, 0x33, 0x64, 0x34, 0x65, 0x31, 0x64, 0x30, 0x33, 0x35, 0x34, 0x32, 0x37, 0x65, 
0x30, 0x32, 0x38, 0x39, 0x34, 0x36, 0x61, 0x39, 0x62, 0x36, 0x61, 0x39, 0x30, 0x32, 0x31, 0x34, 
0x33, 0x37, 0x66, 0x36, 0x38, 0x32, 0x63, 0x37, 0x30, 0x32, 0x34, 0x36, 0x34, 0x37, 0x66, 0x31, 
0x34, 0x32, 0x38, 0x35, 0x31, 0x33, 0x64, 0x65, 0x30, 0x35, 0x31, 0x63, 0x65, 0x33, 0x65, 0x65, 
0x36, 0x34, 0x38, 0x65, 0x37, 0x31, 0x33, 0x33, 0x39, 0x32, 0x36, 0x62, 0x35, 0x35, 0x32, 0x39, 
0x38, 0x32, 0x32, 0x64, 0x66, 0x36, 0x31, 0x36, 0x37, 0x35, 0x36, 0x32, 0x39, 0x36, 0x62, 0x38, 
0x35, 0x1a, 0x28, 0x00, 0x00, 0x13, 0x11, 0x39, 0x22
    };

    /* 填入DHCP模式信息 */
    if (dhcp_on)
        RuijieExtra[0x04] = 0x7f;

    /* 填入IP、掩码、网关、DNS地址信息 */
    ruijie_int32_to_byte (RuijieExtra + 0x5, local_ip);
    ruijie_int32_to_byte (RuijieExtra + 0x9, local_mask);
    ruijie_int32_to_byte (RuijieExtra + 0xd, local_gateway);
    ruijie_int32_to_byte (RuijieExtra + 0x11, local_dns);

    /* 计算信息体的环校验码 0x12 0x13*/
    Blog (RuijieExtra);

    /* 填入版本信息 */
    RuijieExtra[0x3B] = client_ver_val[0];
    RuijieExtra[0x3C] = client_ver_val[1];

    /*****  EAPOL Header  *******/
    uint8_t eapol_eth_header[SIZE_ETHERNET];
    struct ether_header *eth = (struct ether_header *)eapol_eth_header;
    memcpy (eth->ether_dhost, muticast_mac, ETHER_ADDR_LEN);
    memcpy (eth->ether_shost, local_mac, ETHER_ADDR_LEN);
    eth->ether_type =  htons (0x888e);

    /**** EAPol START ****/
    uint8_t start_data[4] = {0x01, 0x01, 0x00, 0x00};
    memset (eapol_start, 0, 1000);
    memcpy (eapol_start, eapol_eth_header, SIZE_ETHERNET);
    memcpy (eapol_start + OFFSET_EAPOL, start_data, sizeof(start_data));
    memcpy (eapol_start + OFFSET_EAP, RuijieExtra, sizeof(RuijieExtra));

    /****EAPol LOGOFF ****/
    uint8_t logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
    memset (eapol_logoff, 0, 1000);
    memcpy (eapol_logoff, eapol_eth_header, SIZE_ETHERNET);
    memcpy (eapol_logoff + OFFSET_EAPOL, logoff_data, sizeof(logoff_data));
    memcpy (eapol_logoff + OFFSET_EAP, RuijieExtra, sizeof(RuijieExtra));


    /* EAP RESPONSE IDENTITY */
    uint8_t eap_resp_iden_head[9] = {0x01, 0x00, 
                                    0x00, 5 + username_length, /* eapol_length */
                                    0x02, 0x01, 
                                    0x00, 5 + username_length, /* eap_length */
                                    0x01};
    data_index = 0;
    memcpy (eap_response_ident + data_index, eapol_eth_header, SIZE_ETHERNET);
    data_index += SIZE_ETHERNET;
    memcpy (eap_response_ident + data_index, eap_resp_iden_head, sizeof(eap_resp_iden_head));
    data_index += sizeof(eap_resp_iden_head);
    memcpy (eap_response_ident + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_ident + data_index, RuijieExtra, sizeof(RuijieExtra));

    /** EAP RESPONSE MD5 Challenge **/
    uint8_t eap_resp_md5_head[10] = {0x01, 0x00, 
                                   0x00, 6 + 16 + username_length,/* eapol_length */
                                   0x02, 0x02, 
                                   0x00, 6 + 16 + username_length,/* eap-length */
                                   0x04, 0x10};
    data_index = 0;
    memcpy (eap_response_md5ch + data_index, eapol_eth_header, SIZE_ETHERNET);
    data_index += SIZE_ETHERNET;
    memcpy (eap_response_md5ch + data_index, eap_resp_md5_head, sizeof(eap_resp_md5_head));
    data_index += sizeof(eap_resp_md5_head) + 16;// 剩余16位在收到REQ/MD5报文后由fill_password_md5填充 
    memcpy (eap_response_md5ch + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_md5ch + data_index, RuijieExtra, sizeof(RuijieExtra));

    /* LIFE KEEP PACKET */
    memcpy (eap_life_keeping, eapol_eth_header, 14);
    uint8_t ruijie_life_keep[] = {0x01,0xBF, 0x00,0x1E,
    0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,
    0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF};
    memcpy (eap_life_keeping + OFFSET_EAPOL, ruijie_life_keep, sizeof(ruijie_life_keep));
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  show_local_info
 *  Description:  显示信息
 * =====================================================================================
 */
void 
show_local_info ()
{
    char    buf[32];
    printf("##### zRuijie for GZHU ver. %s ######\n", ZRJ_VER);
    printf("Device:     %s\n", devname);
    printf("MAC:        %02x:%02x:%02x:%02x:%02x:%02x\n",
                        local_mac[0],local_mac[1],local_mac[2],
                        local_mac[3],local_mac[4],local_mac[5]);
    printf("IP:         %s\n", inet_ntop(AF_INET, &local_ip, buf, 32));
    printf("MASK:       %s\n", inet_ntop(AF_INET, &local_mask, buf, 32));
    printf("Gateway:    %s\n", inet_ntop(AF_INET, &local_gateway, buf, 32));
    printf("DNS:        %s\n", inet_ntop(AF_INET, &local_dns, buf, 32));
    printf("Client ver: %u.%u\n", client_ver_val[0], client_ver_val[1]);
    printf("######################################\n");
}
