#include "ChangeOwner.h"
#include <stdio.h>
#include <Shlwapi.h>
#include <Lm.h>
#include <TCHAR.h>

#define LOGON_MANAGER_SUBKEY	"Software\\Penta Security Systems\\LogonManager"
#define IF_SUBKEY							"Software\\Penta Security Systems\\ISSAC-File"
#define USERMAP_SUBKEY				"SOFTWARE\\Penta Security Systems\\LogonManager\\User Map"
#define WRITE_COUNT						720
#define WRITE_INTERVAL				5000
#define EDITION_SIZE					255
#define EDITION_BUSINESS			"Business"
//TIME_WRITE X WRITE_INTERVAL(1/1000��) = ���� �ϴ� �ð�
static HKEY g_hLogonManagerKey = NULL;
static HKEY g_hIFKey           = NULL;
static BOOL ReadRegValueA(HKEY hKey, char *regValueName, char *regValueDataBuff, size_t regValueDataBuffLen);

static BOOL IsBusiness()
{
	HKEY hEdition = NULL;
	char szEdition[EDITION_SIZE] = {0, };
	DWORD cb = sizeof(szEdition);

	if(ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, IF_SUBKEY, 0, KEY_ALL_ACCESS, &hEdition))
	{
		if(ERROR_SUCCESS == RegQueryValueEx(hEdition, "Edition", NULL,	NULL,	(LPBYTE)szEdition, &cb))
		{
			if(!strcmpi(szEdition, EDITION_BUSINESS))
			{
				RegCloseKey(hEdition);
				return TRUE;
			}
		}
		RegCloseKey(hEdition);
	}
	
	return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance
		  ,LPSTR lpszCmdParam,int nCmdShow)
{
	if(IsBusiness())
		return TRUE;

	BOOL res;
	if (!g_hLogonManagerKey)
	{
		LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOGON_MANAGER_SUBKEY,
			0, KEY_ALL_ACCESS, &g_hLogonManagerKey);
		if (ret != ERROR_SUCCESS)
			return FALSE;
		
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, IF_SUBKEY,
			0, KEY_ALL_ACCESS, &g_hIFKey);
		if (ret != ERROR_SUCCESS){
			RegCloseKey(g_hLogonManagerKey);
			return FALSE;
		}
			
	}
	if(__argc > 1){
		res = SysPwdReset(__argv[1]);
		if(res != TRUE)
			MessageBox(NULL, "SystemAccount PassWord Change Fail!", "ChangeOwner Information", MB_OK);
	}

	res = DeleteUserMapDN();
	if(res != TRUE)
		MessageBox(NULL, "Dn Delete Fail!", "ChangeOwner Information", MB_OK);

	res = IFCONF_StartChangeOwnerProc();
	if(res != TRUE)
		MessageBox(NULL, "Change Owner Registry Set Fail!", "ChangeOwner Information", MB_OK);


	/**
		2008.03.04
		������
		UserMap ���� Dn�� ���� ���� KEY���� 
		����ġ �ϱ� ���Ͽ� �߰��Ͽ��� FindUserMap()�� 
		�ʿ䰡 �������� ���� �ּ� ó��
	*/
	//FindUserMap();
	

	if(g_hIFKey){
		RegCloseKey(g_hIFKey);
		g_hIFKey = NULL;
	}
	if(g_hLogonManagerKey){
		RegCloseKey(g_hLogonManagerKey);
		g_hLogonManagerKey = NULL;
	}
	return 0;
}


BOOL IFCONF_StartChangeOwnerProc()
{
  char ownerAccount[128];
  char ownerDn[256];
  DWORD dwValue;
	
  if (IFCONF_GetOwnerSystemAccountA(ownerAccount, sizeof(ownerAccount)) &&
		IFCONF_GetOwnerDn(ownerDn, sizeof(ownerDn)))
  {
    char ownerAccountInfoRegSubKey[256];
    
    _snprintf(ownerAccountInfoRegSubKey, sizeof(ownerAccountInfoRegSubKey),
			"Account Info\\%s",
			ownerAccount);
		
    HKEY ownerAccountInfoKey;
    LONG ret;
    ret = RegOpenKeyEx(g_hLogonManagerKey, ownerAccountInfoRegSubKey, 0, KEY_ALL_ACCESS,
			&ownerAccountInfoKey);
    if (ret != ERROR_SUCCESS){
			if(g_hIFKey){
				RegCloseKey(g_hIFKey);
				g_hIFKey = NULL;
			}
			if(g_hLogonManagerKey){
				RegCloseKey(g_hLogonManagerKey);
				g_hLogonManagerKey = NULL;
			}

      return FALSE;
		}
    
    DWORD mappingEnabled = 1;
    ret = RegSetValueEx(ownerAccountInfoKey, "Self Mapping", 0, REG_DWORD,
			(LPBYTE)&mappingEnabled, sizeof(mappingEnabled));
    if (ret != ERROR_SUCCESS)
    {
			if(ownerAccountInfoKey){
				RegCloseKey(ownerAccountInfoKey);
				ownerAccountInfoKey = NULL;
			}
			if(g_hIFKey){
				RegCloseKey(g_hIFKey);
				g_hIFKey = NULL;
			}
			if(g_hLogonManagerKey){
				RegCloseKey(g_hLogonManagerKey);
				g_hLogonManagerKey = NULL;
			}
      return FALSE;
    }
		
    ret = RegSetValueEx(ownerAccountInfoKey, "Move State", 0, REG_SZ,
			(LPBYTE)"On", strlen("On") + 1);
    if (ret != ERROR_SUCCESS)
    {
      mappingEnabled = 0;
      RegSetValueEx(ownerAccountInfoKey, "Self Mapping", 0, REG_DWORD,
				(LPBYTE)&mappingEnabled, sizeof(mappingEnabled));
			if(ownerAccountInfoKey){
				RegCloseKey(ownerAccountInfoKey);
				ownerAccountInfoKey = NULL;
			}
			if(g_hIFKey){
				RegCloseKey(g_hIFKey);
				g_hIFKey = NULL;
			}
			if(g_hLogonManagerKey){
				RegCloseKey(g_hLogonManagerKey);
				g_hLogonManagerKey = NULL;
			}
      return FALSE;
    }
		
    ret = RegSetValueEx(g_hLogonManagerKey, "MoveDN",0, REG_SZ,
			(LPBYTE)ownerDn, strlen(ownerDn) + 1);
    if (ret != ERROR_SUCCESS)
    {
      mappingEnabled = 0;
      RegSetValueEx(ownerAccountInfoKey, "Self Mapping", 0, REG_DWORD,
				(LPBYTE)&mappingEnabled, sizeof(mappingEnabled));
      RegSetValueEx(ownerAccountInfoKey, "Move State", 0, REG_SZ,
        (LPBYTE)"Off", strlen("Off") + 1);
			if(ownerAccountInfoKey){
				RegCloseKey(ownerAccountInfoKey);
				ownerAccountInfoKey = NULL;
			}
			if(g_hIFKey){
				RegCloseKey(g_hIFKey);
				g_hIFKey = NULL;
			}
			if(g_hLogonManagerKey){
				RegCloseKey(g_hLogonManagerKey);
				g_hLogonManagerKey = NULL;
			}
      return FALSE;
    }
		
    dwValue = 2;
    ret = RegSetValueEx(g_hLogonManagerKey, "Owner Reset", 0, REG_DWORD,
			(LPBYTE)&dwValue, 4);
    if (ret != ERROR_SUCCESS)
    {
      mappingEnabled = 0;
      RegSetValueEx(ownerAccountInfoKey, "Self Mapping", 0, REG_DWORD,
				(LPBYTE)&mappingEnabled, sizeof(mappingEnabled));
      RegSetValueEx(ownerAccountInfoKey, "Move State", 0, REG_SZ,
        (LPBYTE)"Off", strlen("Off") + 1);
      RegSetValueEx(g_hLogonManagerKey, "MoveDN", 0, REG_SZ,
        (LPBYTE)"", 1);
			if(ownerAccountInfoKey){
				RegCloseKey(ownerAccountInfoKey);
				ownerAccountInfoKey = NULL;
			}
			if(g_hIFKey){
				RegCloseKey(g_hIFKey);
				g_hIFKey = NULL;
			}
			if(g_hLogonManagerKey){
				RegCloseKey(g_hLogonManagerKey);
				g_hLogonManagerKey = NULL;
			}
      return FALSE;
    }
    if(ownerAccountInfoKey){
			RegCloseKey(ownerAccountInfoKey);
			ownerAccountInfoKey = NULL;
		}
		if(g_hIFKey){
			RegCloseKey(g_hIFKey);
			g_hIFKey = NULL;
		}
		if(g_hLogonManagerKey){
			RegCloseKey(g_hLogonManagerKey);
			g_hLogonManagerKey = NULL;
		}
    return TRUE;
  }
  else
  {
		if(g_hIFKey){
			RegCloseKey(g_hIFKey);
			g_hIFKey = NULL;
		}
		if(g_hLogonManagerKey){
			RegCloseKey(g_hLogonManagerKey);
			g_hLogonManagerKey = NULL;
		}
    return FALSE;
  }
}




BOOL IFCONF_GetOwnerSystemAccountA(char *ownerSystemAccountBuff,
                                   size_t ownerSystemAccountBuffLen)
{
  return ReadRegValueA(g_hLogonManagerKey, "ManagerID",
		ownerSystemAccountBuff,
		ownerSystemAccountBuffLen);
}

BOOL IFCONF_GetOwnerDn(char *ownerDnBuff, size_t ownerDnBuffLen)
{
  return ReadRegValueA(g_hLogonManagerKey, "Owner DN",
		ownerDnBuff, ownerDnBuffLen);
}

static BOOL ReadRegValueA(HKEY hKey, char *regValueName,
													char *regValueDataBuff, size_t regValueDataBuffLen)
{
  DWORD regValueType;
  DWORD regValueDataBuffBytesSize;
  LONG ret;
	
  assert(hKey != NULL);
  assert(regValueName != NULL);
  assert(strlen(regValueName) > 0);
  assert(regValueDataBuff != NULL);
  
  regValueDataBuffBytesSize = regValueDataBuffLen;
  ret = RegQueryValueEx(hKey, regValueName, 0, &regValueType,
		(LPBYTE)regValueDataBuff,
		&regValueDataBuffBytesSize);
  
  return (ret == ERROR_SUCCESS);  
}

BOOL FindUserMap(){
	char UserMapSubKey[256];
	char tempSubKey[256];
	char tempLog[1024];
	HKEY hUserMap = NULL;
	HKEY hDN = NULL;
	LONG ret = 0;
	int count=0;
	int countUserMapSubKey;
	char dataKey[128];
	unsigned long dataKeySize = sizeof(dataKey);
	int countDataKey;
	char tempBinary[10];

	if (!hUserMap)
	{
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, USERMAP_SUBKEY,
												0, KEY_ALL_ACCESS, &hUserMap);

		if (ret != ERROR_SUCCESS)
			return FALSE;
	}
	
	
	while(count < WRITE_COUNT){
		countUserMapSubKey = 0;
		memset(tempLog, 0, sizeof(tempLog));

		while(1){
			memset(UserMapSubKey, 0, sizeof(UserMapSubKey));
			
//-----------------------------------------------------------------------------------------
//UserMap �ؿ� �ִ� DN������ while���� ���� ���� ���.
			ret = RegEnumKey(hUserMap, countUserMapSubKey, UserMapSubKey, sizeof(UserMapSubKey));
			if(ret == ERROR_SUCCESS){
				strcat(tempLog, "\n-->DN\t: ");
				strcat(tempLog, UserMapSubKey);
				
				memset(tempSubKey, 0, sizeof(tempSubKey));
				sprintf(tempSubKey, "%s\\%s",USERMAP_SUBKEY, UserMapSubKey);
//-----------------------------------------------------------------------------------------

//-----------------------------------------------------------------------------------------
//�ش� DN������ Key�� ���� �� ������ �ִ� �������� ���
				ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, tempSubKey, 0, KEY_ALL_ACCESS, &hDN);
				if(ret == ERROR_SUCCESS){
					memset(UserMapSubKey, 0, sizeof(UserMapSubKey));
					ret = RegEnumKey(hDN, 0, UserMapSubKey, sizeof(UserMapSubKey));
					if(ret == ERROR_SUCCESS){
						strcat(tempLog, "\nAccount\t: ");
						strcat(tempLog, UserMapSubKey);

//-----------------------------------------------------------------------------------------
//���� �� �����⿡ ���� �Ͽ����Ƿ� �ش� ������ Key�� ���� �Ʒ��� value�� ���.
						if(hDN){
							RegCloseKey(hDN);
							sprintf(tempSubKey, "%s\\%s", tempSubKey, UserMapSubKey);
							ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, tempSubKey, 0, KEY_ALL_ACCESS, &hDN);
							if(ret == ERROR_SUCCESS){
								memset(dataKey, 0, sizeof(dataKey));
								ret = RegQueryValueEx(hDN, "Key", 0, NULL, (LPBYTE)dataKey, &dataKeySize);
								if(ret == ERROR_SUCCESS){
									strcat(tempLog, "\nKey\t: ");
									for(countDataKey=0;countDataKey < dataKeySize;countDataKey++){
										memset(tempBinary,0,sizeof(tempBinary));
										sprintf(tempBinary, "%02x", (BYTE)dataKey[countDataKey]);
										strcat(tempLog, tempBinary);
									}
								}

							}
						}
//-----------------------------------------------------------------------------------------
					}
				}
			}
			else{
				if(hDN){
					RegCloseKey(hDN);
					hDN = NULL;
				}
				break;
			}
			if(hDN){
				RegCloseKey(hDN);
				hDN = NULL;
			}
			countUserMapSubKey++;
		}
		strcat(tempLog, "\n");
		WriteLog(tempLog);
		Sleep(WRITE_INTERVAL);
		count++;
	}
	if(hUserMap)
		RegCloseKey(hUserMap);

	return TRUE;
}

void WriteLog(char* msg){
	FILE* f;
	f = fopen("C:\\UserMapFind.log", "a");
  if(f)
  {
    char szDayOfWeek[10] = {0,};
    SYSTEMTIME st;
    GetLocalTime(&st);
    switch(st.wDayOfWeek)
    {
    case 0:  strcpy(szDayOfWeek, "��");   break;
    case 1:  strcpy(szDayOfWeek, "��");   break;
    case 2:  strcpy(szDayOfWeek, "ȭ");   break;
    case 3:  strcpy(szDayOfWeek, "��");   break;
    case 4:  strcpy(szDayOfWeek, "��");   break;
    case 5:  strcpy(szDayOfWeek, "��");   break;
    case 6:  strcpy(szDayOfWeek, "��");   break;
    default: strcpy(szDayOfWeek, "  ");		break;
    }
		
    fprintf(f,
			"[%s %d-%02d-%02d %02d:%02d:%02d] : %s\r\n",
			szDayOfWeek,
			st.wYear, st.wMonth,  st.wDay,
			st.wHour, st.wMinute, st.wSecond, msg);
    fflush(f);
    fclose(f);
  }
  return;
}

BOOL DeleteUserMapDN(){

	char UserMapSubKey[256];
	HKEY hUserMap = NULL;
	LONG ret = 0;
	

	if (!hUserMap)
	{
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, USERMAP_SUBKEY,
			0, KEY_ALL_ACCESS, &hUserMap);
		
		if (ret != ERROR_SUCCESS)
			return FALSE;
	}


	while(ret != ERROR_NO_MORE_ITEMS){
		memset(UserMapSubKey, 0, sizeof(UserMapSubKey));
		
		//UserMap �ؿ� �ִ� DN������ while���� ���� ���� ���.
		ret = RegEnumKey(hUserMap,0, UserMapSubKey, sizeof(UserMapSubKey));
		/**
			2008.03.04
			������
			dwIndex�� 0���� ���� ��Ų ������ SHDeleteKey()�Լ��� �����ϰ� �Ǹ�
			�ش� SubKey�� �����ǰ� �ٽ� ���� �ȴ�. 
			�� 2���� ������ 1���� ���� �ϸ� ���� SubKey�� Enum�� 0���� ���õȴ�. -_-;;
		*/
		if(ret == ERROR_SUCCESS){
			SHDeleteKey(hUserMap, UserMapSubKey);
		}
	}

	if(hUserMap){
		RegCloseKey(hUserMap);
	}

	return TRUE;
}







BOOL SysPwdReset(char *SysPwd){	 
	HKEY hKey;
	DWORD cb;
	char domain[128];
	wchar_t szAccount[128];
	wchar_t szFormalDomain[128];
	wchar_t NewSysPwd[128];
	wchar_t wchar_temp[128];
	char ownerAccount[128];
	USER_INFO_1003 accountPassword;
	NET_API_STATUS result;

	IFCONF_GetOwnerSystemAccountA(ownerAccount, sizeof(ownerAccount));
	memset(szAccount, 0, sizeof(szAccount));
	memset(NewSysPwd, 0, sizeof(NewSysPwd));
	memset(szFormalDomain, 0, sizeof(szFormalDomain));

	
	mbstowcs(szAccount, ownerAccount, sizeof(szAccount)/sizeof(wchar_t));
	
	RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	 "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", 0,
	 KEY_READ, &hKey);
	cb = sizeof(domain); memset(domain, 0, sizeof(domain));
	RegQueryValueEx(hKey, "ComputerName", 0, NULL,
	 (LPBYTE)domain, &cb);
	RegCloseKey(hKey);

	
	
	mbstowcs(wchar_temp, domain, sizeof(wchar_temp)/sizeof(wchar_t));
	swprintf(szFormalDomain, L"\\\\%s", wchar_temp);



	
	mbstowcs(NewSysPwd, SysPwd, sizeof(NewSysPwd)/sizeof(wchar_t));

	accountPassword.usri1003_password = NewSysPwd;

/* Debug
	MessageBoxW(0,szFormalDomain,L"Debug?",0);
	MessageBoxW(0,szAccount,L"Debug?",0);
	MessageBoxW(0,NewSysPwd,L"Debug?",0);
*/
	
	
	result = NetUserSetInfo(szFormalDomain, szAccount, 1003, 
	 (LPBYTE)&accountPassword, NULL);

	if(result == NERR_GroupExists)
		MessageBox(NULL, "NERR_GroupExists", "Information", MB_OK);
	if(result != NERR_Success){
		LPVOID lpMsgBuf;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR) &lpMsgBuf, 0, NULL );
		 
			MessageBox(NULL, (LPTSTR)lpMsgBuf, "NewUserSetInfo Information", MB_OK);
			LocalFree( lpMsgBuf );

		RegCloseKey(hKey);
		return FALSE;
	}
	return TRUE;
}



















