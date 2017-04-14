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
    \date    2009-03-04 오후 3:42:17
    \author  정연욱
    \brief   HKEY_LOCAL_MACHINE\SOFTWARE\Penta Security Systems\LogonManager\User Map 밑의 모든 값을 삭제 한다.

    \return 성공 실패의 여부
    \sa			None
*/
BOOL DeleteUserMapDN();




/*** SysPwdReset ***/
/** 
    \ingroup ChangeOwner
    \date    2009-03-04 오후 8:27:49
    \author  정연욱
    \brief   System 계정 패스워드를 변경한다.


    \return 성공 실패의 여부
    \sa			None
*/
BOOL SysPwdReset(char *SysPwd);

void WriteLog(char* msg);