/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/06/2009 03:45:21 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "zruijie.h"

#define LOCKFILE "/var/run/zruijie.pid"

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static void signal_interrupted (int signo);

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
        exit(1);
    }
 
    //把pid写入锁文件
    ftruncate (lockfile, 0);    
    sprintf (buf, "%ld", (long)getpid());
    write (lockfile, buf, strlen(buf) + 1);
}


void
daemon_init(void)
{
	pid_t	pid;

	if ( (pid = fork()) < 0)
	    perror ("Fork");
	else if (pid != 0) {
        fprintf(stdout, "&&Info: ZDClient Forked background with PID: [%d]\n\n", pid);
		exit(0);
    }
	setsid();		/* become session leader */
	chdir("/");		/* change working directory */
	umask(0);		/* clear our file mode creation mask */

    flock_reg ();
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
        exit(1);
    }
    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg ();
        return 0;
    }
    else {
        if (exit_flag) {
            if ( kill (fl.l_pid, SIGINT) == -1 ) {
                            perror("kill");
                            exit(EXIT_FAILURE);
            }
            fprintf (stdout, "&&Info: Kill Signal Sent to PID %d.\n", fl.l_pid);
            exit (EXIT_FAILURE);
        }
    }
    return fl.l_pid;
}



int main(int argc, char **argv)
{
    init_arguments (&argc, &argv);
    //打开锁文件
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        perror ("Lockfile");
        exit(1);
    }

    int ins_pid;
    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@ERROR: ZDClient Already "
                            "Running with PID %d\n", ins_pid);
        exit(EXIT_FAILURE);
    }

    init_info();
    init_device();
    init_frames ();

    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    
    show_local_info();

//    send_eap_packet (EAPOL_LOGOFF);
    send_eap_packet (EAPOL_START);

	pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
    return 0;
}

static void
signal_interrupted (int signo)
{
    fprintf(stdout,"\n&&Info: USER Interrupted. \n");
    send_eap_packet(EAPOL_LOGOFF);
    pcap_breakloop (handle);
    pcap_close (handle);
    exit (EXIT_SUCCESS);
}



