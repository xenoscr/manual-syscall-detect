#pragma once

#define WIN32_NO_STATUS
#define DEBUG_VERBOSE

#include <Windows.h>

#undef WIN32_NO_STATUS

//#include "nativeteb.h"
#include <DbgHelp.h>
#include <ntstatus.h>
#include <stdio.h>
//#include <winternl.h>
#include <TlHelp32.h>

#pragma comment (lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28
#define IP_SANITY_CHECK(ip,BaseAddress,ModuleSize) (ip > BaseAddress) && (ip < (BaseAddress + ModuleSize))

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static DWORD_PTR g_NtdllBase;
static DWORD_PTR g_W32UBase;

static DWORD g_NtdllSize;
static DWORD g_W32USize;

typedef void(*CallbackFn)();

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	CallbackFn Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PULONG RegionSize,
	ULONG AllocationType,
	ULONG Protect);

pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSetInformationProcess");
pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll"), "NtAllocateVirtualMemory");

VOID GetBaseAddresses(VOID);
const wchar_t* GetWC(const char*);
void DebugOut(const wchar_t*, ...);
extern "C" void InstrumentationCallbackProxy(VOID);
#ifdef _WIN64
extern "C" void InstrumentationCallback(PCONTEXT, uintptr_t, uintptr_t);
#else
extern "C" void InstrumentationCallback(uintptr_t, uintptr_t);
#endif
NTSTATUS SetInstrumentationCallbackHook(HANDLE, BOOL);
extern "C" int hookmain(VOID);

VOID GetBaseAddresses() {

	PIMAGE_DOS_HEADER piDH;
	PIMAGE_NT_HEADERS piNH;

	g_NtdllBase = (DWORD_PTR)GetModuleHandle(TEXT("ntdll.dll"));
	piDH = (PIMAGE_DOS_HEADER)g_NtdllBase;
	piNH = (PIMAGE_NT_HEADERS)(g_NtdllBase + piDH->e_lfanew);

	g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

	g_W32UBase = (DWORD_PTR)GetModuleHandle(TEXT("win32u.dll"));
	if (g_W32UBase) {
		piDH = (PIMAGE_DOS_HEADER)g_W32UBase;
		piNH = (PIMAGE_NT_HEADERS)(g_W32UBase + piDH->e_lfanew);
		g_W32USize = piNH->OptionalHeader.SizeOfImage;
	}
}

// https://stackoverflow.com/questions/8032080/how-to-convert-char-to-wchar-t
const wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

//https://gist.github.com/syu5-gh/eaa0018ed70836b7279b
void DebugOut(const wchar_t *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	wchar_t dbg_out[4096];
	vswprintf_s(dbg_out, fmt, argp);
	va_end(argp);
	OutputDebugString(dbg_out);
}

void InstrumentationCallback(
#ifdef _WIN64
	PCONTEXT ctx,
#endif
	uintptr_t ReturnAddress, 
	uintptr_t ReturnVal
)
{
	BOOLEAN sanityCheckNt;
	BOOLEAN sanityCheckWu;
	DWORD_PTR NtdllBase;
	DWORD_PTR W32UBase;
	DWORD NtdllSize;
	DWORD W32USize;
	int cbDisableOffset;
	int instPrevSpOffset;
	int instPrevPcOffset;
#ifdef _DEBUG
	BOOLEAN SymbolLookupResult = FALSE;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	BYTE SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
#endif

	uintptr_t pTEB = (uintptr_t)NtCurrentTeb();

#ifdef _WIN64
	cbDisableOffset = 0x02EC;	// TEB64->InstrumentationCallbackDisabled offset
	instPrevPcOffset = 0x02D8;	// TEB64->InstrumentationCallbackPreviousPc offset
	instPrevSpOffset = 0x02E0;  // TEB64->InstrumentationCallbackPreviousSp offset
	ctx->Rip = *((uintptr_t*)(pTEB + instPrevPcOffset));
	ctx->Rsp = *((uintptr_t*)(pTEB + instPrevSpOffset));
	ctx->Rcx = ctx->R10;
	ctx->R10 = ctx->Rip;
#else
	//PTEB32 pTEB = (PTEB32)NtCurrentTeb();
	cbDisableOffset = 0x01B8;   // TEB32->InstrumentationCallbackDisabled offset
	instPrevPcOffset = 0x01B0;  // TEB32->InstrumentationCallbackPreviousPc offset
	instPrevSpOffset = 0x01B4;  // TEB32->InstrumentationCallbackPreviousSp offset
#endif

	//
	// Check TEB->InstrumentaionCallbackDisabled flag to prevent recursion.
	//
	if (!*((uintptr_t*)(pTEB + cbDisableOffset))) {
		//
		// Disabling to prevent recursion. Do not call any 
		// Win32 APIs outside of this loop and before
		// setting the TEB->InstrumentationCallbackDisabled flag
		// 
		*((uintptr_t*)(pTEB + cbDisableOffset)) = 1;

#ifdef _DEBUG
		// Lookup and display the Symbol Name if found
		SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymbolInfo->MaxNameLen = MAX_SYM_NAME;

		SymbolLookupResult = SymFromAddr(NtCurrentProcess(), ReturnAddress, &Displacement, SymbolInfo);

		if (SymbolLookupResult)
			DebugOut(L"[+] Symbol name: %s\n", GetWC(SymbolInfo->Name));

#ifdef DEBUG_VERBOSE
#ifdef _WIN64
			DebugOut(L"[d] CTX->Rip: 0x%016Ix\n", ctx->Rip);
#endif
			DebugOut(L"[d] ReturnAddress: 0x%016Ix\n", ReturnAddress);
			DebugOut(L"[d] ReturnVal: 0x%016Ix\n", ReturnVal);
#endif
#endif

		// Get pointers to DLL base addresss & sizes
		NtdllBase = (DWORD_PTR)InterlockedCompareExchangePointer(
			(PVOID*)&g_NtdllBase,
			NULL,
			NULL
		);

		W32UBase = (DWORD_PTR)InterlockedCompareExchangePointer(
			(PVOID*)&g_W32UBase,
			NULL,
			NULL
		);

		NtdllSize = InterlockedCompareExchange(
			(DWORD*)&g_NtdllSize,
			NULL,
			NULL
		);

		W32USize = InterlockedCompareExchange(
			(DWORD*)&g_W32USize,
			NULL,
			NULL
		);
		
		// Check to see if the syscall came from within the DLLs
#ifdef _WIN64
		sanityCheckNt = IP_SANITY_CHECK(ctx->Rip, NtdllBase, NtdllSize);
		sanityCheckWu = IP_SANITY_CHECK(ctx->Rip, W32UBase, W32USize);
#else
		sanityCheckNt = IP_SANITY_CHECK(ReturnAddress, NtdllBase, NtdllSize);
		sanityCheckWu = IP_SANITY_CHECK(ReturnAddress, W32UBase, W32USize);
#endif

		// If the syscall did not come from the a know DLL, print a message and break.
		if (!(sanityCheckNt || sanityCheckWu)) {
			DebugOut(L"[!] Kernel returns to unverified module.\n");
#ifdef _WIN64
			DebugOut(L"[I] CTX->Rip: 0x%016Ix\n", ctx->Rip);
#else
			DebugOut(L"[I] ReturnAddress: 0x%016Ix\n", ReturnAddress);
			DebugOut(L"[I] ReturnVal: 0x%016Ix\n", ReturnVal);
#endif

#ifdef _DEBUG
			if (SymbolLookupResult)
				DebugOut(L"[!] Unverified function: %s\n", GetWC(SymbolInfo->Name));

			// Un-commnet if you want to manually debug
			// DebugBreak();
#endif
			// Terminate the process
			DebugOut(L"[!] Preventing further execution!\n");
			ExitProcess(ERROR_INVALID_ACCESS);
		}

		// Unset TEB->InstrumentationCallbackDisabled to re-enable
		// instrumention.
		*((uintptr_t*)(pTEB + cbDisableOffset)) = 0;
	}
#ifdef _WIN64
	RtlRestoreContext(ctx, NULL);
#endif
}

// Code inspired by ScyllaHide - https://github.com/x64dbg/ScyllaHide/blob/master/HookLibrary/HookHelper.cpp
NTSTATUS SetInstrumentationCallbackHook(HANDLE ProcessHandle, BOOL Enable)
{
	CallbackFn Callback = Enable ? InstrumentationCallbackProxy : NULL;

	// Windows 10
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo;
#ifdef _WIN64
	CallbackInfo.Version = 0;
#else
	// Native x86 instrumentation callbacks don't work correctly
	BOOL Wow64Process = FALSE;
	if (!IsWow64Process(ProcessHandle, &Wow64Process) || !Wow64Process)
	{
		//Info.Version = 1; // Value to use if they did
		return STATUS_NOT_SUPPORTED;
	}

	// WOW64: set the callback pointer in the version field
	CallbackInfo.Version = (ULONG)Callback;
#endif
	CallbackInfo.Reserved = 0;
	CallbackInfo.Callback = Callback;

	return NtSetInformationProcess(ProcessHandle, ProcessInstrumentationCallback,
		&CallbackInfo, sizeof(CallbackInfo));
}

extern "C"
int hookmain()
{
	GetBaseAddresses();
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(NtCurrentProcess(), NULL, TRUE);

#ifdef _WINDLL
	// Nothing
#else
	AllocConsole();
#endif
	DebugOut(L"[+] Logging started...\n");
	DebugOut(L"[+] ntdll BaseAddress: 0x%016Ix\n", g_NtdllBase);
	DebugOut(L"[+] win32u BaseAddress: 0x%016Ix\n", g_W32UBase);

	if (!NT_SUCCESS(SetInstrumentationCallbackHook(NtCurrentProcess(), TRUE)))
	{
		DebugOut(L"[!] Failed to set hook\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#ifdef _WINDLL
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpReserved)
#else
int main()
#endif
{
#ifdef _WINDLL
	UNREFERENCED_PARAMETER(lpReserved);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		hookmain();
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		SetInstrumentationCallbackHook(NtCurrentProcess(), FALSE);
		break;

	case DLL_PROCESS_DETACH:
		SetInstrumentationCallbackHook(NtCurrentProcess(), FALSE);
		break;
	}
	// Return true or the DLL will unload/cause process to exit.
	return TRUE;
#else
	PVOID test = NULL;
	SIZE_T regSize = 0x1000;

	NtAllocateVirtualMemory(NtCurrentProcess(), &test, 0, (PULONG)&regSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SetInstrumentationCallbackHook(NtCurrentProcess(), FALSE);

	return 0;
#endif
}
