#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include "rsrc.inc"
#include "commondef.h"
#include "eap_protocol.h"

LPCTSTR reg_key = "Software\\ZRuijie4Gzhu";

INT_PTR     CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD       WINAPI eap_thread();

void        init_combo_list();
void        on_button_connect_clicked (void);
void        on_button_exit_clicked ();
void        on_chkbox_save_clicked ();
void        on_chkbox_auto_clicked ();
void        update_interface_state();
void        reg_info_dword(LPCTSTR lpSubKey, LPCTSTR val_key, 
                BOOL ForceWrite, DWORD def_val, DWORD *val);
DWORD       reg_info_string (LPCTSTR lpSubKey, LPCTSTR val_key,  BOOL write,
                const char *def_val, char *val, DWORD val_len);
void        init_info();
                        
BOOL save_checked;
BOOL auto_checked;
int  combo_index;

extern enum STATE state;

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
    HICON hIcon, hIconSm;

    InitCommonControls();

    hwndDlg = CreateDialog(hInstance, 
            MAKEINTRESOURCE(IDD_DLG_ZRJ), NULL, DlgProc);

    hwndEditUser = GetDlgItem (hwndDlg, IDC_EDT_USR);
    hwndEditPass = GetDlgItem (hwndDlg, IDC_EDT_PAS);
    hwndButtonConn = GetDlgItem (hwndDlg, IDC_BTN_CONN);
    hwndButtonExit = GetDlgItem (hwndDlg, IDC_BTN_EXIT);
    hwndComboList = GetDlgItem (hwndDlg, IDC_CBO_LIST);

    hIcon = LoadImage(GetModuleHandle(NULL), 
            MAKEINTRESOURCE(IDI_ICON_RJ), IMAGE_ICON, 32, 32, 0);
    hIconSm = LoadImage(GetModuleHandle(NULL), 
            MAKEINTRESOURCE(IDI_ICON_RJ), IMAGE_ICON, 16, 16, 0);

    SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconSm);

    init_combo_list();
    init_info();

    while( GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int) msg.wParam;
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
                    on_button_connect_clicked();
                    break;
                case IDC_BTN_EXIT:
                    on_button_exit_clicked ();
                    break;
                case IDC_CHK_SAVE:
                    on_chkbox_save_clicked();
                    break;
                case IDC_CHK_AUTO:
                    on_chkbox_auto_clicked();
                    break;
            }
        }
        else if (HIWORD(wParam) == CBN_SELCHANGE) {
            combo_index = SendMessage(hwndComboList, CB_GETCURSEL, 0, 0);
        }
        break;
    case WM_CLOSE:
         PostQuitMessage (0);
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
        
        if (save_checked) {
            reg_info_string (reg_key, "usr", TRUE, username, NULL, 0);
            reg_info_string (reg_key, "psw", TRUE, password, NULL, 0);
        }
    }
    
    reg_info_dword (reg_key, "if_index", TRUE, combo_index, NULL);
    reg_info_dword (reg_key, "save_checked", TRUE, save_checked, NULL);
    reg_info_dword (reg_key, "auto_checked", TRUE, auto_checked, NULL);
    
    EnableWindow (hwndButtonConn, FALSE);
    EnableWindow (hwndEditUser, FALSE);
    EnableWindow (hwndEditPass, FALSE);
    EnableWindow (hwndComboList, FALSE);
    
    hEAP_THREAD = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)eap_thread, 0, 0, 0);

}

void on_button_exit_clicked ()
{
    if (state == READY)
        PostQuitMessage(0);
    else
        send_eap_packet (EAPOL_LOGOFF);
}

void on_chkbox_save_clicked()
{
    BOOL savechek = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVE);

    if (savechek == BST_UNCHECKED && auto_checked == BST_CHECKED) {
        CheckDlgButton(hwndDlg, IDC_CHK_AUTO, BST_UNCHECKED);
    }

    save_checked = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVE);
    auto_checked = IsDlgButtonChecked(hwndDlg, IDC_CHK_AUTO);
}

void on_chkbox_auto_clicked()
{
    BOOL savechek = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVE);

    if (savechek == BST_UNCHECKED) 
        CheckDlgButton(hwndDlg, IDC_CHK_SAVE, BST_CHECKED);
    
    save_checked = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVE);
    auto_checked = IsDlgButtonChecked(hwndDlg, IDC_CHK_AUTO);
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
    }
    else if (state == CONNECTING) {
        SetWindowText (hwndButtonConn, TEXT("Connecting..."));
        SetWindowText (hwndButtonExit, TEXT("Logoff"));
    }
    else if (state == ONLINE) {
        SetWindowText (hwndButtonConn, TEXT("Connected"));
        SetWindowText (hwndButtonExit, TEXT("Logoff"));
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
    

    reg_info_dword (reg_key, "save_checked", FALSE, BST_UNCHECKED, (DWORD*)&save_checked);
    reg_info_dword (reg_key, "auto_checked", FALSE, BST_UNCHECKED, (DWORD*)&auto_checked);
    CheckDlgButton(hwndDlg, IDC_CHK_SAVE, save_checked);
    CheckDlgButton(hwndDlg, IDC_CHK_AUTO, auto_checked);
    

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
