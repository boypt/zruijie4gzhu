#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include "rsrc.inc"
#include "commondef.h"
#include "eap_protocol.h"

#define TRAYICONID	1//				ID number for the Notify Icon
#define SWM_TRAYMSG	WM_APP//		the message ID sent to our window

#define SWM_SHOW	WM_APP + 1//	show the window
#define SWM_HIDE	WM_APP + 2//	hide the window
#define SWM_EXIT	WM_APP + 3//	close the window
#define SWM_CONN    WM_APP + 4
#define SWM_LOGOFF  WM_APP + 5

LPCTSTR reg_key = "Software\\ZRuijie4Gzhu";

INT_PTR     CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD       WINAPI eap_thread();

void        InitProgram ();
void        init_combo_list();
void        on_button_connect_clicked (void);
void        on_button_exit_clicked ();

void        update_interface_state();
void        reg_info_dword(LPCTSTR lpSubKey, LPCTSTR val_key, 
                BOOL ForceWrite, DWORD def_val, DWORD *val);
DWORD       reg_info_string (LPCTSTR lpSubKey, LPCTSTR val_key,  BOOL write,
                const char *def_val, char *val, DWORD val_len);
void        init_info();
void        on_close_window_clicked();
void        on_program_quit ();
void        ShowTrayMenu(HWND hWnd);

                        
BOOL auto_con;
BOOL auto_min;
int  combo_index;

extern enum STATE state;

NOTIFYICONDATA	niData;	// notify icon data

HWND hwndDlg;
HWND hwndEditUser;
HWND hwndEditPass;
HWND hwndButtonConn;
HWND hwndButtonExit;
HWND hwndComboList;

HANDLE hEAP_THREAD;
HANDLE hLIFE_KEEP_THREAD;
HANDLE hEXIT_WAITER;

#ifdef  __DEBUG
void debug_msgbox (const char *fmt, ...)
{
    va_list args;
    char msg[1024];
    va_start (args, fmt);
    vsnprintf (msg, 1024, fmt, args);
    va_end (args);
    MessageBox (hwndDlg, TEXT(msg), NULL, MB_OK);
}
#endif     /* -----  not __DEBUG  ----- */

int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR lpCmdLine, int nCmdShow )
{
    MSG  msg ;

    InitCommonControls();

    hwndDlg = CreateDialog(hInstance, 
            MAKEINTRESOURCE(IDD_DLG_ZRJ), NULL, DlgProc);

    InitProgram ();
    init_combo_list();
    init_info();

    if (auto_con) 
        on_button_connect_clicked();

    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int) msg.wParam;
}

void InitProgram ()
{
    HICON hIcon, hIconSm;

    hwndEditUser = GetDlgItem (hwndDlg, IDC_EDT_USR);
    hwndEditPass = GetDlgItem (hwndDlg, IDC_EDT_PAS);
    hwndButtonConn = GetDlgItem (hwndDlg, IDC_BTN_CONN);
    hwndButtonExit = GetDlgItem (hwndDlg, IDC_BTN_EXIT);
    hwndComboList = GetDlgItem (hwndDlg, IDC_CBO_LIST);

    hIcon = LoadImage(GetModuleHandle(NULL), 
            MAKEINTRESOURCE(IDI_ICON_RJ), IMAGE_ICON, 32, 32, 0);
    hIconSm = LoadImage(GetModuleHandle(NULL), 
            MAKEINTRESOURCE(IDI_ICON_RJ), IMAGE_ICON, 16, 16, 0);

    //set application icon
    SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconSm);

    /* Add icon to system tray */
	ZeroMemory(&niData,sizeof(NOTIFYICONDATA));
	
    niData.cbSize = sizeof(NOTIFYICONDATA);

	niData.uID = TRAYICONID;
	niData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	niData.hIcon = hIconSm;
	niData.hWnd = hwndDlg;
    niData.uCallbackMessage = SWM_TRAYMSG;
    lstrcpyn(niData.szTip, TEXT("zRuijie for GZHU"), sizeof(niData.szTip)/sizeof(TCHAR));

	Shell_NotifyIcon(NIM_ADD,&niData);

}

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED) {
                switch (LOWORD(wParam))
                {
                    case IDC_BTN_CONN:
                    case SWM_CONN:
                        on_button_connect_clicked();
                        break;
                    case IDC_BTN_EXIT:
                    case SWM_LOGOFF:
                        on_button_exit_clicked ();
                        break;
                    case IDC_CHK_AUTO_CON:
                        auto_con = IsDlgButtonChecked(hwnd, IDC_CHK_AUTO_CON);
                        reg_info_dword (reg_key, "auto_con", TRUE, auto_con, NULL);
                        break;
                    case IDC_CHK_AUTO_MIN:
                        auto_min = IsDlgButtonChecked(hwnd, IDC_CHK_AUTO_MIN);
                        reg_info_dword (reg_key, "auto_min", TRUE, auto_min, NULL);
                        break;

                    case SWM_SHOW:
                        ShowWindow(hwnd, SW_RESTORE);
                        break;
                    case SWM_HIDE:
                    case IDOK:
                        ShowWindow(hwnd, SW_HIDE);
                        break;
                    case SWM_EXIT:
                        on_program_quit();
                        break;
                }
            }
            else if (HIWORD(wParam) == CBN_SELCHANGE) {
                combo_index = SendMessage(lParam, CB_GETCURSEL, 0, 0);
            }
            break;
        case SWM_TRAYMSG:
            switch(lParam)
            {
                case WM_LBUTTONDBLCLK:
                    if (IsWindowVisible(hwnd))
                        ShowWindow(hwnd, SW_HIDE);
                    else
                        ShowWindow(hwnd, SW_RESTORE);
                    break;
                case WM_RBUTTONDOWN:
                case WM_CONTEXTMENU:
                    ShowTrayMenu(hwnd);
                    break;
            }
            break;
        case WM_CLOSE:
            on_close_window_clicked();
            break;
    }
    return FALSE;
}

void on_button_connect_clicked (void)
{
    extern char      username[];
    extern char      password[];
    extern int       username_length, password_length;

    if (Edit_GetModify(hwndEditUser) || Edit_GetModify (hwndEditPass)) {
    
        username_length = GetWindowTextLength(hwndEditUser);
        password_length = GetWindowTextLength(hwndEditPass);
    
        GetWindowText(hwndEditUser, username, username_length + 1);
        GetWindowText(hwndEditPass, password, password_length + 1);
        
        reg_info_string (reg_key, "usr", TRUE, username, NULL, 0);
        reg_info_string (reg_key, "psw", TRUE, password, NULL, 0);
    }
    
    reg_info_dword (reg_key, "if_index", TRUE, combo_index, NULL);
    
    EnableWindow (hwndButtonConn, FALSE);
    EnableWindow (hwndEditUser, FALSE);
    EnableWindow (hwndEditPass, FALSE);
    EnableWindow (hwndComboList, FALSE);
    
    hEAP_THREAD = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)eap_thread, 0, 0, 0);

}

void on_program_quit ()
{
	niData.uFlags = 0;
	Shell_NotifyIcon(NIM_DELETE,&niData);
	PostQuitMessage(0);
}

void on_close_window_clicked()
{
    if (state == READY) 
        on_program_quit();
    else
        ShowWindow (hwndDlg, SW_HIDE);
}

void on_button_exit_clicked ()
{
    if (state == READY)
        on_program_quit();
    else
        send_eap_packet (EAPOL_LOGOFF);
}

DWORD WINAPI eap_thread()
{
    extern pcap_t *handle;
    extern char    devname[];
    
    init_device();
    init_frames ();
    send_eap_packet (EAPOL_START);
    pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
    pcap_close (handle);

    memset (devname, 0, MAX_DEV_NAME_LEN);
    update_interface_state(NULL);
    return 0;
}

void update_interface_state(const char *msg)
{
    if (state == READY) {
        SetWindowText (hwndButtonConn, TEXT("Connect"));
        SetWindowText (hwndButtonExit, TEXT("Exit"));
        EnableWindow (hwndButtonExit, TRUE);
        EnableWindow (hwndButtonConn, TRUE);
        EnableWindow (hwndEditUser, TRUE);
        EnableWindow (hwndEditPass, TRUE);
        EnableWindow (hwndComboList, TRUE);
        if (!IsWindowVisible(hwndDlg))
            ShowWindow(hwndDlg, SW_RESTORE);
    }
    else if (state == CONNECTING) {
        SetWindowText (hwndButtonConn, TEXT("Connecting..."));
        SetWindowText (hwndButtonExit, TEXT("Logoff"));
    }
    else if (state == ONLINE) {
        SetWindowText (hwndButtonConn, TEXT("Connected"));
        /* if auto hide */
        if (auto_min && IsWindowVisible(hwndDlg))
            ShowWindow(hwndDlg, SW_HIDE);        
    }
    else if (state == LOGOFF) {
        SetWindowText (hwndButtonConn, TEXT(msg));
        EnableWindow (hwndButtonExit, FALSE);
    }
}

void init_combo_list()
{
    char            errbuf[PCAP_ERRBUF_SIZE];   /* error buffer */
    pcap_if_t       *alldevs;
    pcap_if_t         *d;
    pcap_addr_t     *a;
    BOOL            flag = FALSE;
    int             i = 0;
    int             index;
    
    /* Retrieve the device list */
    assert(pcap_findalldevs(&alldevs, errbuf) != -1);

    for (d = alldevs; d; d = d->next, ++i) {
        SendMessage(hwndComboList, CB_ADDSTRING, 0, (LPARAM)d->description);
        for(a = d->addresses; a; a=a->next) {
            if (flag) break;
            if (a->addr->sa_family == AF_INET) {
                flag = TRUE;
                //SendMessage(hwndComboList, CB_SETCURSEL, (WPARAM)i, 0);
                index = i;
                break;
            }
        }
    }
    pcap_freealldevs(alldevs);
    
    reg_info_dword (reg_key, "if_index", FALSE, index, (DWORD*)&combo_index);

    if (index == combo_index)
        SendMessage(hwndComboList, CB_SETCURSEL, (WPARAM)index, 0);
    else
        SendMessage(hwndComboList, CB_SETCURSEL, (WPARAM)combo_index, 0);
        
}

void edit_info_append (const char *msg)
{
    HWND hwndEditInfo;
    int len;

    hwndEditInfo = GetDlgItem (hwndDlg, IDC_EDT_INFO); 

    len = GetWindowTextLength (hwndEditInfo);
    SetFocus (hwndEditInfo);
    Edit_SetSel (hwndEditInfo, len, len);
    Edit_ReplaceSel (hwndEditInfo, msg);
}

void reg_info_dword(LPCTSTR lpSubKey, LPCTSTR val_key, BOOL ForceWrite,
                                DWORD def_val, DWORD *val)
{
    long lRet;
    HKEY hKey;

    DWORD dwSize;

    lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE,lpSubKey,0,NULL,
        REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey, NULL);
    
    if(lRet == ERROR_SUCCESS){            
        dwSize = sizeof(*val);
        lRet = RegQueryValueEx(hKey,val_key,
                0, NULL,(LPBYTE)val, &dwSize);    
        if(lRet != ERROR_SUCCESS || ForceWrite)
        {
            RegSetValueEx(hKey,val_key,
                   0, REG_DWORD,(LPBYTE)&def_val, sizeof(def_val));
            if (val != NULL)
                *val = def_val;
        }
    }
    RegCloseKey(hKey);
}
DWORD reg_info_string (LPCTSTR lpSubKey, LPCTSTR val_key,  BOOL write,
                              const char *def_val, char *val, DWORD val_len)
{
    long lRet;
    DWORD qret;
    HKEY hKey;

    lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE,lpSubKey,0,NULL,
        REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL, &hKey, NULL);
    
    if(lRet == ERROR_SUCCESS){            
        qret = RegQueryValueEx(hKey,val_key,
                0, NULL, (LPBYTE)val, &val_len);
        
        if(write) {
            RegSetValueEx(hKey,val_key,
                   0, REG_SZ,(LPBYTE)def_val, strlen(def_val));
        }
    }
    RegCloseKey(hKey);
    return qret;
}

void init_info()
{
    extern uint32_t  ruijie_live_serial_num;
    extern uint8_t   client_ver_val[];
    extern char      username[];
    extern char         password[];
    extern int          username_length, password_length;
    extern int         dhcp_on;
    
    if ((reg_info_string 
            (reg_key, "usr", FALSE, NULL, username, 64) == ERROR_SUCCESS) &&
        (reg_info_string
            (reg_key, "psw", FALSE, NULL, password, 64) == ERROR_SUCCESS)){
        username_length = strlen (username);
        password_length = strlen (password);
        Edit_SetText (hwndEditUser, TEXT(username));
        Edit_SetText (hwndEditPass, TEXT(password));
//        MessageBox (NULL, username, NULL, NULL);
    }
    

    reg_info_dword (reg_key, "auto_con", FALSE, BST_UNCHECKED, (DWORD*)&auto_con);
    reg_info_dword (reg_key, "auto_min", FALSE, BST_UNCHECKED, (DWORD*)&auto_min);
    CheckDlgButton(hwndDlg, IDC_CHK_AUTO_CON, auto_con);
    CheckDlgButton(hwndDlg, IDC_CHK_AUTO_MIN, auto_min);
    
    reg_info_dword (reg_key, "client_ver_0",             FALSE, 3, (DWORD*)&client_ver_val[0]);
    reg_info_dword (reg_key, "client_ver_1",             FALSE, 50, (DWORD*)&client_ver_val[1]);
    reg_info_dword (reg_key, "dhcp_on",                 FALSE,  1, (DWORD*)&dhcp_on);
    reg_info_dword (reg_key, "ruijie_live_serial_num", FALSE, 0x0000102b, (DWORD*)&ruijie_live_serial_num);
}

void thread_error_exit(const char *errmsg) 
{
    MessageBox (hwndDlg, errmsg, NULL, MB_OK);
    update_interface_state (NULL);
    ExitThread(0);
}

void ShowTrayMenu(HWND hwnd)
{
	POINT pt;
	GetCursorPos(&pt);
	HMENU hMenu;

	hMenu = CreatePopupMenu();

	if(hMenu)
	{
		if( IsWindowVisible(hwnd) )
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_HIDE, TEXT("Hide"));
		else
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_SHOW, TEXT("Show"));
        if (state == READY)
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_CONN, TEXT("Connect"));
        else
            InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_LOGOFF, TEXT("Log Off"));
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_EXIT, TEXT("Exit"));
		// note:	must set window to the foreground or the
		//			menu won't disappear when it should
		SetForegroundWindow(hwnd);

		TrackPopupMenuEx(hMenu, TPM_BOTTOMALIGN | TPM_LEFTBUTTON | TPM_RIGHTBUTTON,
			pt.x, pt.y, hwnd, NULL );
		DestroyMenu(hMenu);
	}
}
