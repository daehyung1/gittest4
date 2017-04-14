#include <windows.h>
#include <assert.h>

BOOL IFCONF_GetOwnerSystemAccountA(char *ownerSystemAccountBuff, size_t ownerSystemAccountBuffLen);

BOOL IFCONF_GetOwnerDn(char *ownerDnBuff, size_t ownerDnBuffLen);

BOOL IFCONF_StartChangeOwnerProc();

BOOL FindUserMap();

static INT_PTR CALLBACK PasswdResetDlgProc(
																					 HWND    hwndDlg,
																					 UINT    uMsg,
																					 WPARAM  wParam,
																					 LPARAM  lParam);


/*** DeleteUserMapDN ***/
/** 
    \ingroup ChangeOwner
    \date    2009-03-04 ���� 3:42:17
    \author  ������
    \brief   HKEY_LOCAL_MACHINE\SOFTWARE\Penta Security Systems\LogonManager\User Map ���� ��� ���� ���� �Ѵ�.

    \return ���� ������ ����
    \sa			None
*/
BOOL DeleteUserMapDN();




/*** SysPwdReset ***/
/** 
    \ingroup ChangeOwner
    \date    2009-03-04 ���� 8:27:49
    \author  ������
    \brief   System ���� �н����带 �����Ѵ�.


    \return ���� ������ ����
    \sa			None
*/
BOOL SysPwdReset(char *SysPwd);

void WriteLog(char* msg);