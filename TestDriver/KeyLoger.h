#pragma once
#include <ntddk.h>

typedef struct tagDeviceExtension
{
	PDEVICE_OBJECT pLowerDeviceObject; //���ڼ�¼��һ����ε��豸����
	PDEVICE_OBJECT pTargetDeviceObject; //���ڼ�¼��һ����ε��豸����

}DEVICEEXTENSION, *PDEVICEEXTENSION;

typedef struct tagThreadContext
{
	LIST_ENTRY keyLst;   //���ڼ�¼ÿһ�����̵���������
	KSPIN_LOCK spinLock; //������
	KSEMAPHORE semLock;  //�źŵ�
	int  bTerminate;     //������־
	PETHREAD pThreadObj; //�߳̾��
	HANDLE hLogFile;     //��־�ļ����

}THREADCONTEXT, *PTHREADCONTEXT;

extern POBJECT_TYPE *IoDriverObjectType;
extern THREADCONTEXT g_ThreadContext;

NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
);