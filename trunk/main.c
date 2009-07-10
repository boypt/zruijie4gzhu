/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/06/2009 08:19:17 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */



#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "commondef.h"
#include "eap_protocol.h"

#define LOCKFILE "/var/run/zruijie.pid"

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern pcap_t      *handle;
extern int          exit_flag;

int                 lockfile;                  /* 锁文件的描述字 */

void
flock_reg ()
{
    char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();
 
    //阻塞式的加锁
    if (fcntl (lockfile, F_SETLKW, &fl) < 0){
        perror ("fcntl_reg");
        exit(EXIT_FAILURE);
    }
 
    //把pid写入锁文件
    assert (0 == ftruncate (lockfile, 0) );    
    sprintf (buf, "%ld", (long)getpid());
    assert (-1 != write (lockfile, buf, strlen(buf) + 1));
}


void
daemon_init(void)
{
	pid_t	pid;
    int     fd0;

	if ( (pid = fork()) < 0)
	    perror ("Fork");
	else if (pid != 0) {
        fprintf(stdout, "&&Info: Forked background with PID: [%d]\n\n", pid);
		exit(EXIT_SUCCESS);
    }
	setsid();		/* become session leader */
	assert (0 == chdir("/tmp"));		/* change working directory */
	umask(0);		/* clear our file mode creation mask */
    flock_reg ();

    fd0 = open ("/dev/null", O_RDWR);
    dup2 (fd0, STDIN_FILENO);
    dup2 (fd0, STDERR_FILENO);
    dup2 (fd0, STDOUT_FILENO);
    close (fd0);
}


int 
program_running_check()
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
 
    //尝试获得文件锁
    if (fcntl (lockfile, F_GETLK, &fl) < 0){
        perror ("fcntl_get");
        exit(EXIT_FAILURE);
    }

    if (exit_flag) {
        if (fl.l_type != F_UNLCK) {
            if ( kill (fl.l_pid, SIGINT) == -1 )
                perror("kill");
            fprintf (stdout, "&&Info: Kill Signal Sent to PID %d.\n", fl.l_pid);
        }
        else 
            fprintf (stderr, "&&Info: NO zRuijie Running.\n");
        exit (EXIT_FAILURE);
    }


    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg ();
        return 0;
    }

    return fl.l_pid;
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
 *         Name:  init_arguments
 *  Description:  初始化和解释命令行的字符串。getopt_long
 * =====================================================================================
 */
void init_arguments(int *argc, char ***argv)
{
    extern int         dhcp_on;               /* DHCP 模式标记 */
    extern int         background;            /* 后台运行标记  */
    extern int         exit_flag;
    extern char        *dev;               /* 连接的设备名 */
    extern char        *username;          
    extern char        *password;
    extern char        *user_gateway;      /* 由用户设定的四个报文参数 */
    extern char        *user_dns;           /* 字符串内保存点分ip格式ASCII */
    extern char        *user_ip;
    extern char        *user_mask;
    extern char        *client_ver;         /* 报文协议版本号 */
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
                if (optopt == 'u' || optopt == 'p'||
                        optopt == 'g'|| optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                fprintf (stderr,"Unknown option character `\\x%x'.\n", c);
                exit(EXIT_FAILURE);
        }
    }    
}


static void
signal_interrupted (int signo)
{
    extern int exit_flag;
    if (exit_flag)
        exit (EXIT_SUCCESS);
    exit_flag = 1;
    fprintf(stdout,"\n&&Info: Interrupted. \n");
    send_eap_packet(EAPOL_LOGOFF);
}

void *
thread_wait_exit (void *arg)
{
    int i = 10;
    do {
        fprintf(stdout, "Please wait until session ends ... %2d\r", i);
        fflush (stdout);
        sleep (1);
    }while (i--);
    fprintf(stdout, "\n&&Info: Program Exit.         \n");
    pcap_breakloop (handle);
    return ((void*)0);
}


int main(int argc, char **argv)
{
    int ins_pid;

    init_arguments (&argc, &argv);

    //打开锁文件
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        perror ("Lockfile");
        exit(EXIT_FAILURE);
    }

    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@ERROR: zRuijie Already "
                            "Running with PID %d\n", ins_pid);
        exit(EXIT_SUCCESS);
    }
    init_info();
    init_device();
    init_frames ();

    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    
    show_local_info();

    send_eap_packet (EAPOL_START);
	pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
    pcap_close (handle);
    return 0;
}



