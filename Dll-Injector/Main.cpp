#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

std::string GetProcessName();
std::string GetDllName();
DWORD GetProcessID( const char *pszProcessName );
void BypassTrusted( const HANDLE &hProcess );

int main()
{
	const std::string szProcessName = GetProcessName();
	const std::string szDllName = GetDllName();

	char szDllPath[ MAX_PATH ];
	GetFullPathName( szDllName.c_str(), MAX_PATH, szDllPath, 0 );

	DWORD dwProcessID = 0;

	while( !dwProcessID )
	{
		dwProcessID = GetProcessID( szProcessName.c_str() );
		Sleep( 50 );
	}

	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, 0, dwProcessID );

	if( hProcess )
	{
		if( !strcmp( szProcessName.c_str(), "csgo.exe" ) )
		{
			BypassTrusted( hProcess );
		}

		void *pBaseAddress = VirtualAllocEx( hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		if( pBaseAddress )
		{
			if( WriteProcessMemory( hProcess, pBaseAddress, szDllPath, MAX_PATH, 0 ) )
			{
				HANDLE hThread = CreateRemoteThread( hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pBaseAddress, 0, nullptr );

				if( hThread )
				{
					std::cout << "Successfully injected, have fun!" << std::endl;
					Sleep( 1000 );

					CloseHandle( hThread );
					CloseHandle( hProcess );
				}
			}
		}
	}
}

std::string GetProcessName()
{
	std::string szOutput{};

	std::cout << "Please enter the target process name:" << std::endl;
	std::cin >> szOutput;

	if( !strstr( szOutput.c_str(), ".exe" ) )
	{
		szOutput.append( ".exe" );
	}

	return szOutput;
}

std::string GetDllName()
{
	std::string szOutput{};

	std::cout << "Please enter the target dll name:" << std::endl;
	std::cin >> szOutput;

	if( !strstr( szOutput.c_str(), ".dll" ) )
	{
		szOutput.append( ".dll" );
	}

	return szOutput;
}

DWORD GetProcessID( const char *pszProcessName )
{
	DWORD dwProcessID = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if( hSnap )
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof( pe32 );

		if( Process32First( hSnap, &pe32 ) )
		{
			do
			{
				if( !strcmp( pe32.szExeFile, pszProcessName ) )
				{
					dwProcessID = pe32.th32ProcessID;
					break;
				}

			} while( Process32Next( hSnap, &pe32 ) );
		}

		CloseHandle( hSnap );
	}

	return dwProcessID;
}

void BypassTrusted( const HANDLE &hProcess )
{
	HMODULE hModule = LoadLibrary( "ntdll" );

	if( hModule )
	{
		void *pNtOpenFile = GetProcAddress( hModule, "NtOpenFile" );

		if( pNtOpenFile )
		{
			char cOriginalBytes[ 5 ];
			memcpy( cOriginalBytes, pNtOpenFile, 5 );
			WriteProcessMemory( hProcess, pNtOpenFile, cOriginalBytes, 5, 0 );
		}
	}
}