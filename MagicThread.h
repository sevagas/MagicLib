#pragma once

#ifndef _Thread_H_
#define _Thread_H_

#include <string>
#include <vector>


#include "Magic.h"

enum KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
};

enum THREAD_STATE
{
	Running = 2,
	Waiting = 5,
};


/* Structure useful to manipulate thread context */
typedef struct _REMOTE_THREAD_CONTEXT_MANIPULATION {
	HANDLE hProcess;
	HANDLE hThread;
	CONTEXT savedThreadContext;
	BOOL isThreadSuspended;
	ADDRESS_VALUE writeGadgetAddr;
	ADDRESS_VALUE jmp0GadgetAddr;
	ADDRESS_VALUE jmp0StackAddr;
	BOOL createNewThread;
}REMOTE_THREAD_CONTEXT_MANIPULATION, * PREMOTE_THREAD_CONTEXT_MANIPULATION;


class MagicThread
{
public:

	/**
	 * Create a  thread in stealthy way
	 * Cannot pass parameter as its used for stezlth	 
	 */
	static HANDLE CreateStealthThread(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		LPVOID                  lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);

	/**
	 * Create a remote thread in stealthy way
	 * Cannot pass parameter as its used for stezlth
	 * https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread
	 */
	static HANDLE CreateStealthRemoteThread(
		HANDLE                 hProcess,
		LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		SIZE_T                 dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		DWORD                  dwCreationFlags,
		LPDWORD                lpThreadId
	);


	/**
	 * Create a remote thread in stealthy way
	 * Cannot pass parameter as its used for stezlth
	 * https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread
	 */
	static HANDLE CreateStealthRemoteThread(
		HANDLE                 hProcess,
		LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		SIZE_T                 dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID                 lpParameter,
		DWORD                  dwCreationFlags,
		LPDWORD                lpThreadId
	);


	/*
	From https://github.com/odzhan/injection/blob/master/apc/apc.c
	// Try to find thread in alertable state for opened process.
	// This is based on code used in AtomBombing technique.
	//
	// https://github.com/BreakingMalwareResearch/atom-bombing
	//
	*/
	static HANDLE FindAlertableThread(HANDLE hProcess);

	/*
	Initialization fonction required before calling WriteToRemoteThread and CallRemoteProc
	If createNewThread is true, this will call createRemoteThread in suspended state to generate the thread we use to manipulate context
	return TRUE if function succeeds
	*/
	static BOOL InitThreadContextManipulation(HANDLE hProcess, PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation, BOOL createNewThread);

	/*
	Will clean when you are finished with context manipulation
	Will terminate created thead or restore hijacked thread
	return TRUE if function succeeds
	*/
	static BOOL EndThreadContextManipulation(PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation);

	/*
	Use context manipulation to write valueToWrite at addressToWrite in another process
	rtManipulation must have been previously initialized by a call to MagicThread::InitThreadContextManipulation
	*/
	static VOID WriteToRemoteThread(PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation, ULONG_PTR addressToWrite, ADDRESS_VALUE valueToWrite);


	/*
	Trigger a function is another process, 4 parameters can be passed
	rtManipulation must have been previously initialized by a call to MagicThread::InitThreadContextManipulation
	*/
	static ADDRESS_VALUE  TriggerFunctionInRemoteProcess(
		PREMOTE_THREAD_CONTEXT_MANIPULATION rtManipulation,
		CONST TCHAR* moduleName,
		CONST TCHAR* functionName,
		ADDRESS_VALUE          param1 = 0,
		ADDRESS_VALUE          param2 = 0,
		ADDRESS_VALUE          param3 = 0,
		ADDRESS_VALUE          param4 = 0
	);

	/*
	Find  a suspended thread in a given process.
	Return a HANDLE to suspended thread if foud. Return NULL if not.
	*/
	static DWORD FindSuspendedThread(DWORD pid);
	
	/*
	Attempt to get a handle from the first thread which allows it for the dwDesiredAccess flags
	It is poaaible to to run additional check by passing a callback. Set to NULL if you do not use.
	*/
	static HANDLE GetAnyValidThreadHandle(DWORD dwDesiredAccess, BOOL (*ConditionCheckCallback)(HANDLE hThread));

	/*
	Get a thread ID for a given process. Probably the main thread but no guarantee.
	*/
	static DWORD GetThreadIdFromProcess(DWORD pid);

};


#endif