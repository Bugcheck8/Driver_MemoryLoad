

#include "MemoryLoad.h"
#include "shellcode.h"
#include "tools.h"


//ʵ�ֽ��������ص��ڴ�
//���ã�����Ϸɨ���������
//��һ�ַ�������ȡ����ģ���ַ�Լ�����ģ���С�������ڴ棬������ڴ渴��һ�ݣ��޸��ض�λ����CALL��ڵ㣬����ʵ���ڴ����
//ȱ�㣺��Ϊ�������޸��ض�λǰ��VMP������VMP�ͱȽϴ����������������������ױ���⡣
//�ڶ��ַ�����ͨ��ZwQuerySystemInformation������ģ���ַ�޸������

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{

	if (pDriverObject->DeviceObject)
	{

		IoDeleteDevice(pDriverObject->DeviceObject);
	}

}

NTSTATUS DriverEntry(PDRIVER_OBJECT Pdriver, PUNICODE_STRING pReg) {
	
	//DbgBreakPoint();
	//AlloccateMemory(PAGE_SIZE);
	//return STATUS_UNSUCCESSFUL;


	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)Pdriver->DriverSection;
	ForceDeleteSys(ldr->FullDllName.Buffer);

	/*
	//��һ�ַ�����
	//��һ�������������Ĵ�С����һ��Ƿ�ҳ�ڴ�
	//һ��Ҫ�ǷǷ�ҳ������Ƿ�ҳ�ڴ棬��ô�ڴ治����ʱ�򣬻�д��pagefile.sys��ȥ����ҳ�н�������ô������صĹ����г������ǻ�ӹܲ���ȱҳ�쳣����ΪӲ���жϵĵȼ���������ж�
	PUCHAR memory = ExAllocatePool(NonPagedPool, Pdriver->DriverSize);

	//�ڶ��������������׵�ַ���ص�����ڴ���ȥ
	memcpy(memory, Pdriver->DriverStart, Pdriver->DriverSize);
	*/
	//QueryModule("xxxxxxxx", NULL);
	//��һ������ȡ����ģ�����ַ
	//ULONG_PTR ModuleImageBase = QueryModule("CEA.sys", NULL);
	//DbgPrintEx(77, 0, "[db]:%llx\r\n", ModuleImageBase);

	//�ڶ�������ȡ�����ļ���׼�����쵽�ڴ�

	int size = sizeof(ShellData);
	PUCHAR CodeMemory = ExAllocatePool(PagedPool, size);
	memcpy(CodeMemory, ShellData, size);
	//����
	UCHAR key = ShellData[3] - 3;
	for (int i=0;i<size;i++)
	{
		CodeMemory[i] = (CodeMemory[i] ^ ((key + i) & 0xff));
	}
	//DbgBreakPoint();

	
	MemLoadLibrary(CodeMemory, size);
	ExFreePool(CodeMemory);
	Pdriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}