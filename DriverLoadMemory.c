

#include "MemoryLoad.h"
#include "shellcode.h"
#include "tools.h"


//实现将驱动加载到内存
//作用：过游戏扫描驱动检测
//第一种方法：获取驱动模块地址以及驱动模块大小，申请内存，把这块内存复制一份，修复重定位，再CALL入口点，即可实现内存加载
//缺点：因为必须在修复重定位前加VMP，本身VMP就比较大，拉伸玩运行起来更大，容易被检测。
//第二种方法：通过ZwQuerySystemInformation来遍历模块地址修复导入表

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
	//第一种方法：
	//第一步：根据驱动的大小申请一块非分页内存
	//一定要是非分页，如果是分页内存，那么内存不够的时候，会写到pagefile.sys中去，分页中讲过。那么如果加载的过程中出错，我们会接管不了缺页异常，因为硬件中断的等级高于软件中断
	PUCHAR memory = ExAllocatePool(NonPagedPool, Pdriver->DriverSize);

	//第二步：将驱动的首地址加载到这块内存中去
	memcpy(memory, Pdriver->DriverStart, Pdriver->DriverSize);
	*/
	//QueryModule("xxxxxxxx", NULL);
	//第一步：获取驱动模块基地址
	//ULONG_PTR ModuleImageBase = QueryModule("CEA.sys", NULL);
	//DbgPrintEx(77, 0, "[db]:%llx\r\n", ModuleImageBase);

	//第二步：读取驱动文件，准备拉伸到内存

	int size = sizeof(ShellData);
	PUCHAR CodeMemory = ExAllocatePool(PagedPool, size);
	memcpy(CodeMemory, ShellData, size);
	//解密
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