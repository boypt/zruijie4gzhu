#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include "commondef.h"
#include "eap_protocol.h"

#define ID_EDIT_USER 1
#define ID_EDIT_PASS 2
#define ID_BUTTON_CONN 3
#define ID_BUTTON_EXIT 4
#define ID_CHKBOX_SAVE 5
#define ID_CHKBOX_AUTO 6
LPCTSTR reg_key = "Software\\ZRuijie4Gzhu";

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void    InitDialog(HINSTANCE hInstance);
void     init_combo_list();
void    on_button_connect_clicked (void);
void     on_button_exit_clicked ();
void     on_chkbox_save_clicked ();
void     on_chkbox_auto_clicked ();
DWORD   WINAPI eap_thread();
void     update_interface_state();
void     reg_info_dword(LPCTSTR lpSubKey, LPCTSTR val_key, BOOL ForceWrite, DWORD def_val, DWORD *val);
DWORD     reg_info_string (LPCTSTR lpSubKey, LPCTSTR val_key,  BOOL write,
                              const char *def_val, char *val, DWORD val_len);
void     init_info();
                        
BOOL save_checked;
BOOL auto_checked;
int  combo_index;

extern enum STATE state;
HFONT hFont;
HWND hwndWin;
HWND hwndEditUser;
HWND hwndEditPass;
HWND hwndButtonConn;
HWND hwndButtonExit;
HWND hwndComboList;
HWND hwndChkBoxSave;
HWND hwndChkBoxAuto;
HWND hwndEditInfo;

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
    MessageBox (hwndWin, TEXT(msg), NULL, MB_OK);
}
#endif     /* -----  not __DEBUG  ----- */

int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
            LPSTR lpCmdLine, int nCmdShow )
{
     MSG  msg ;    
     InitCommonControls();
     InitDialog(hInstance);
     init_combo_list();
     init_info();
     while( GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
     }
     return (int) msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
  switch(msg)
  {
    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam))
            {
                case ID_BUTTON_CONN:
                    on_button_connect_clicked();
                    break;
                case ID_BUTTON_EXIT:
                    on_button_exit_clicked ();
                    break;
                case ID_CHKBOX_SAVE:
                    on_chkbox_save_clicked();
                    break;
                case ID_CHKBOX_AUTO:
                    on_chkbox_auto_clicked();
                    break;
            }
        }
        else if (HIWORD(wParam) == CBN_SELCHANGE) {
            combo_index = SendMessage(hwndComboList, CB_GETCURSEL, 0, 0);
        }
    break;
    case WM_DESTROY:
        PostQuitMessage(0);
    break;
  }
  return DefWindowProc(hwnd, msg, wParam, lParam);
}

void InitDialog(HINSTANCE hInstance)
{
    WNDCLASS wc = {0};

    HWND hwndStatUser;
    HWND hwndStatPass;


    
    wc.lpszClassName = TEXT( "zRuijie4GZHU" );
    wc.hInstance     = hInstance ;
    wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
    wc.lpfnWndProc   = WndProc ;
    wc.hCursor       = LoadCursor(0,IDC_ARROW);
    RegisterClass(&wc);
    
    hwndWin = CreateWindow( wc.lpszClassName, TEXT("zRuijie4GZHU"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                220, 220, 180, 250, 0, 0, hInstance, 0);
                
    hwndStatUser = CreateWindow(TEXT("static"), TEXT("Username"), 
            WS_CHILD | WS_VISIBLE,
            10, 10, 50, 14,
            hwndWin, NULL, NULL, NULL);
            
    hwndStatPass = CreateWindow(TEXT("static"), TEXT("Password"), 
            WS_CHILD | WS_VISIBLE,
            10, 35, 50, 14,
            hwndWin, NULL, NULL, NULL);
            
    hwndEditUser = CreateWindow(TEXT("edit"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER,
                65, 10, 95, 18, hwndWin, (HMENU) ID_EDIT_USER,
                NULL, NULL);
                
    hwndEditPass = CreateWindow(TEXT("edit"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                65, 35, 95, 18, hwndWin, (HMENU) ID_EDIT_PASS,
                NULL, NULL);
                
    hwndChkBoxSave =   CreateWindow(TEXT("button"), TEXT("Save"),
                 WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                 10, 60, 50, 14, hwndWin, (HMENU) ID_CHKBOX_SAVE, 
                 NULL, NULL);
                 
    hwndChkBoxAuto = CreateWindow(TEXT("button"), TEXT("Auto Conn."),
                 WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                 90, 60, 80, 14, hwndWin, (HMENU) ID_CHKBOX_AUTO, 
                 NULL, NULL);
                 
    hwndButtonConn = CreateWindow(TEXT("button"), TEXT("Connect"), WS_VISIBLE | WS_CHILD,  
                10, 80, 70, 25, hwndWin, (HMENU) ID_BUTTON_CONN, 
                NULL, NULL); 
                
    hwndButtonExit = CreateWindow(TEXT("button"), TEXT("Exit"), WS_VISIBLE | WS_CHILD,  
                90, 80, 70, 25, hwndWin, (HMENU) ID_BUTTON_EXIT, 
                NULL, NULL); 
                
    hwndComboList = CreateWindow(TEXT("combobox"), NULL, WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,  
                10, 110, 150, 25, hwndWin, (HMENU) ID_BUTTON_EXIT, 
                NULL, NULL); 
    
    hwndEditInfo = CreateWindow(TEXT("edit"), NULL, WS_VISIBLE | WS_VSCROLL | WS_BORDER | WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL |ES_WANTRETURN | ES_READONLY,
                10, 140, 150, 70, hwndWin, NULL, NULL, NULL); 
                
    hFont = CreateFont(8, 0, 0, 0, FW_MEDIUM, 0, 0, 0, 0, 0, 0, 0, 0, TEXT("MS Sans Serif"));

    SendMessage (hwndStatUser, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndStatPass, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndEditUser, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndEditPass, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndButtonConn, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndButtonExit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndComboList, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndChkBoxSave, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndChkBoxAuto, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage (hwndEditInfo, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void on_button_connect_clicked (void)
{
    extern char      username[];
    extern char         password[];
    extern int          username_length, password_length;

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
    BOOL savechek = IsDlgButtonChecked(hwndWin, ID_CHKBOX_SAVE);

    if (savechek == BST_UNCHECKED && auto_checked == BST_CHECKED) {
        CheckDlgButton(hwndWin, ID_CHKBOX_AUTO, BST_UNCHECKED);
    }

    save_checked = IsDlgButtonChecked(hwndWin, ID_CHKBOX_SAVE);
    auto_checked = IsDlgButtonChecked(hwndWin, ID_CHKBOX_AUTO);
}

void on_chkbox_auto_clicked()
{
    BOOL savechek = IsDlgButtonChecked(hwndWin, ID_CHKBOX_SAVE);

    if (savechek == BST_UNCHECKED) 
        CheckDlgButton(hwndWin, ID_CHKBOX_SAVE, BST_CHECKED);
    
    save_checked = IsDlgButtonChecked(hwndWin, ID_CHKBOX_SAVE);
    auto_checked = IsDlgButtonChecked(hwndWin, ID_CHKBOX_AUTO);
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
    
    reg_info_dword (reg_key, "if_index", FALSE, index, &combo_index);

    if (index == combo_index)
        SendMessage(hwndComboList, CB_SETCURSEL, (WPARAM)index, 0);
    else
        SendMessage(hwndComboList, CB_SETCURSEL, (WPARAM)combo_index, 0);
        
}

void edit_info_append (const char *msg)
{
    int len;
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
    CheckDlgButton(hwndWin, ID_CHKBOX_SAVE, save_checked);
    CheckDlgButton(hwndWin, ID_CHKBOX_AUTO, auto_checked);
    

    reg_info_dword (reg_key, "client_ver_0",             FALSE, 3, (DWORD*)&client_ver_val[0]);
    reg_info_dword (reg_key, "client_ver_1",             FALSE, 50, (DWORD*)&client_ver_val[1]);
    reg_info_dword (reg_key, "dhcp_on",                 FALSE,  1, (DWORD*)&dhcp_on);
    reg_info_dword (reg_key, "ruijie_live_serial_num", FALSE, 0x0000102b, (DWORD*)&ruijie_live_serial_num);
}

void thread_error_exit(const char *errmsg) 
{
    MessageBox (hwndWin, errmsg, NULL, MB_OK);
    update_interface_state (NULL);
    ExitThread(0);
}
