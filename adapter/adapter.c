#include<windows.h>
//#include <winsock2.h>

#include <stdio.h>
#include <stdlib.h>


#define IOCTL_DRIVER  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

ULONG  registerService();
ULONG  StopService();





int __cdecl main(int argc, char **argv)
{
	
	DWORD   s, result;
	HANDLE  hDevice;
	BOOL    l;	
	char    pointer[20][64];
	int     i, lenParams = 0;

	memset( pointer, 0, 20*64);
	
	if( argc>20 )
		return 1;
	
	if( argc == 2 )
	{
		if( lstrcmpA( argv[1], "stop" ) == 0)
		{
			result = StopService();
			return result;
		}
	}

	i = argc-1;
	memcpy(pointer[0], &i , sizeof(int));
    for( i=1 ; i< argc ; i++ )
    {
		if( lstrlenA(argv[i])>64)
			continue;

		lstrcpyA( pointer[i], argv[i]);
		lenParams = lenParams + lstrlenA(argv[i]);
    }


	result = registerService();
	if( result == 0 )
	{
		hDevice = CreateFile(L"\\\\.\\StreamFirewall",
									 GENERIC_READ|GENERIC_WRITE,
									 0,
									 NULL,
									 OPEN_EXISTING,
									 FILE_FLAG_OVERLAPPED,
									 NULL );
	
		l = DeviceIoControl( hDevice, IOCTL_DRIVER, pointer, 20*64, 0, 0, &s, 0);
		s = GetLastError();



		CloseHandle( hDevice);
	}
	else
	{
		 printf("registerService failed (%d)\n", result);
	}

	return result;
}

ULONG  registerService()
{
	HANDLE hToken;             
    TOKEN_PRIVILEGES tkp;
    SC_HANDLE schSCManager, schService;
	DWORD error;
	BOOL l;
	char    system_directory[MAX_PATH];


	if (!OpenProcessToken(GetCurrentProcess(), 
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
					 return GetLastError(); 

     LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, 
							&tkp.Privileges[0].Luid);  

	 tkp.PrivilegeCount = 1;    
	 tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

	 l = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, 
						(PTOKEN_PRIVILEGES) NULL, 0); 

    schSCManager = OpenSCManagerA( 
        NULL,                    
        NULL,                    
        SC_MANAGER_ALL_ACCESS);  

	if (NULL == schSCManager) 
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return GetLastError();
    }

    if( !GetSystemDirectoryA( system_directory, MAX_PATH))
    {
        printf("GetSystemDirectory failed (%d)\n", GetLastError());
        return GetLastError();
    }

	lstrcatA( system_directory, "\\drivers\\firewall.sys");
    schService = CreateServiceA( 
        schSCManager,         
        "StreamFirewall",       
        "StreamFirewall",       
        SERVICE_ALL_ACCESS,   
        SERVICE_KERNEL_DRIVER,
        SERVICE_AUTO_START, 
        SERVICE_ERROR_NORMAL, 
        system_directory,      
        NULL,                 
        NULL,                 
        NULL,                 
        NULL,                 
        NULL);    

	 if (NULL == schService) 
     {
		error = GetLastError();
        if( error != ERROR_SERVICE_EXISTS)
		{
			printf("CreateService failed (%d)\n", error);
			return error;
		}
		else
		{
			schService = OpenServiceA( schSCManager, "StreamFirewall", SERVICE_ALL_ACCESS);
		}
     }
	
     l = StartServiceA( schService, 0, NULL);
	 //l = DeleteService( schService );
	 l = CloseServiceHandle( schService );
	 l = CloseServiceHandle( schSCManager );

  /*  if( !GetSystemDirectoryA( system_directory, MAX_PATH))
		return 1;
	lstrcatA( system_directory, "\\drivers\\StreamFirewall.sys");
    schService2 = CreateServiceA( 
        schSCManager,         
        "StreamFirewall",       
        "StreamFirewall",       
        SERVICE_ALL_ACCESS,   
        SERVICE_KERNEL_DRIVER,
        SERVICE_AUTO_START, 
        SERVICE_ERROR_NORMAL, 
        system_directory,      
        NULL,                 
        NULL,                 
        NULL,                 
        NULL,                 
        NULL);    

	 

	 if (NULL == schService2) 
     {
		error = GetLastError();
        if( error != ERROR_SERVICE_EXISTS)
		{
			printf("CreateService failed (%d)\n", error);
			return error;
		}
		else
		{
			schService2 = OpenServiceA( schSCManager, "StreamFirewall", SERVICE_ALL_ACCESS);
		}
     }
	 l = CloseServiceHandle( schService2 );
	 l = CloseServiceHandle( schSCManager );

	 DWORD  lRet, Start;
	 HKEY   hKey;
	 char   path[MAX_PATH];
	 //NTSTATUS  nt;
	 //UNICODE_STRING  name_driver;


	 lstrcpyA( path, "\\SystemRoot\\system32\\drivers\\StreamFirewall.sys");
	 
	 lRet = RegCreateKeyA( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\StreamFirewall",  &hKey );
	 if( lRet != ERROR_SUCCESS )
		 return lRet;
	 Start = 1;
     lRet = RegSetValueExA( hKey, "Start", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

	 Start = 1;
     lRet = RegSetValueExA( hKey, "Type", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;
     lRet = RegSetValueExA( hKey, "ErrorControl", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

 
	 lRet = RegSetValueExA( hKey, "ImagePath", 0, REG_SZ, (BYTE*)path, (lstrlenA(path)));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

	 RegCloseKey( hKey );

	 lstrcpyA( path, "\\SystemRoot\\system32\\drivers\\StreamFirewall.sys");
	 
	 lRet = RegCreateKeyA( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\StreamFirewall",  &hKey );
	 if( lRet != ERROR_SUCCESS )
		 return lRet;
	 Start = 2;
     lRet = RegSetValueExA( hKey, "Start", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

	 Start = 1;
     lRet = RegSetValueExA( hKey, "Type", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;
     lRet = RegSetValueExA( hKey, "ErrorControl", 0, REG_DWORD, (BYTE*)&Start, sizeof(DWORD));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

 
	 lRet = RegSetValueExA( hKey, "ImagePath", 0, REG_SZ, (BYTE*)path, (lstrlenA(path)));
	 if( lRet != ERROR_SUCCESS )
		 return lRet;

	 RegCloseKey( hKey );
	 
	 if( !(RtlInitUnicodeString =
			(void(__stdcall*)(PUNICODE_STRING,PCWSTR)) GetProcAddress( GetModuleHandleA("ntdll.dll"),
			 "RtlInitUnicodeString" )) )
    return 1;

	 if( !(ZwLoadDriver =
			(NTSTATUS(__stdcall *)(PUNICODE_STRING)) GetProcAddress( GetModuleHandleA("ntdll.dll"),
			 "ZwLoadDriver" )) )
    return 1;

	WCHAR daPath[] = L"\\SystemRoot\\system32\\drivers\\StreamFirewall.sys";
	RtlInitUnicodeString(  &name_driver, daPath );
    nt = ZwLoadDriver( &name_driver );
	*/

	return 0;
}

ULONG  StopService()
{
	//HANDLE hToken;             
    //TOKEN_PRIVILEGES tkp;
    SC_HANDLE schSCManager, schService;

	BOOL l;
	//char    system_directory[MAX_PATH];
	SERVICE_STATUS service_status;

	 schSCManager = OpenSCManagerA(NULL, NULL, 
        SC_MANAGER_ALL_ACCESS);

      if(!schSCManager)
      {
			printf("OpenSCManagerA failed (%d)\n", GetLastError());
			return GetLastError();
      }

    

      schService = OpenServiceA( schSCManager, "StreamFirewall", SERVICE_ALL_ACCESS);
	  if(!schService)
      {
			printf("OpenService failed (%d)\n", GetLastError());
			return GetLastError();
      }
      
      ControlService(schService, 
        SERVICE_CONTROL_STOP, &service_status);
      
      
     l = CloseServiceHandle( schService );
	 l = CloseServiceHandle( schSCManager );

	 return 0;
}