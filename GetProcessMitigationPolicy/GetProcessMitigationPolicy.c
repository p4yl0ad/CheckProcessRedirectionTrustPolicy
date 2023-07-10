#include <stdio.h>
#include <Windows.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>

void PrintInfo(HANDLE handle)
{
	PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY pmrtp = {0};
	
	BOOL gpmpreturnval = GetProcessMitigationPolicy(
		handle,
		ProcessRedirectionTrustPolicy,
		&pmrtp,
		sizeof(pmrtp)
	);

	if (!gpmpreturnval)
	{
		wprintf(L"[ERROR] GetProcessMitigationPolicy failed with error {%d}\n", GetLastError());
		return;
	}

	wprintf(L"AuditRedirectionTrust( %d ),EnforceRedirectionTrust( %d )\n", pmrtp.AuditRedirectionTrust, pmrtp.EnforceRedirectionTrust);
	
	//wprintf("Process {}\n");
}

void main()
{
	/*
	* Enable SeDebugPrivilege
	* Reference: https://github.com/nettitude/DLLInjection/blob/master/Nettitude/Injection/SeDebugPrivilege.cpp
	*/

	HANDLE hToken;
	LUID luid = { 0 };
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

			if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
				printf("[-] Error: Your current token does not contain the SeDebugPrivilege.\n");
				printf("[-] Please rerun as administrator.");
				exit(-1);
			}
		}
	}

	HANDLE snap = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS, 
		0
	);

	if (snap == INVALID_HANDLE_VALUE) {
		wprintf(L"[ERROR] CreateToolhelp32Snapshot failed with INVALID_HANDLE_VALUE {%d}\n", 
			GetLastError()
		);
		exit(-1);
	}

	PROCESSENTRY32W mod;
	mod.dwSize = sizeof(mod);
	BOOL cont = Process32FirstW(snap, &mod);

	while (cont) {
		wprintf(L"%ls,", mod.szExeFile);

		HANDLE hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			mod.th32ProcessID
		);

		if (hProcess == INVALID_HANDLE_VALUE) {
			wprintf(L"[ERROR] OpenProcess failed with INVALID_HANDLE_VALUE {%d}\n", 
				GetLastError()
			);
			exit(-1);
		}

		// Do stuff..
		PrintInfo(hProcess);

		CloseHandle(hProcess);

		cont = Process32NextW(snap, &mod);
	}
	CloseHandle(snap);
}