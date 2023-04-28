#include "tools.h"
#include <ntimage.h>


//ZwQuerySystemInformation函数是一个Windows系统API函数，用于获取系统信息。它的参数包括：
//1. SystemInformationClass：一个枚举类型，指定要查询的系统信息类型。常用的系统信息类型包括：
//- SystemBasicInformation：获取系统基本信息，如系统时间、CPU架构等。
//- SystemProcessInformation：获取进程信息，如进程ID、父进程ID、线程数等。
//- SystemDriverInformation：获取设备驱动程序信息，如驱动程序名称、文件路径等。
//- SystemHandleInformation：获取系统句柄信息，如句柄类型、句柄值等。
//- SystemModuleInformation：获取系统模块信息，如模块基址、大小、名称等。
//2. SystemInformation：一个指向缓冲区的指针，用于存储查询到的系统信息。
//3. SystemInformationLength：一个无符号整数，指定缓冲区的大小，必须大于等于查询到的系统信息的大小，否则函数会返回STATUS_INFO_LENGTH_MISMATCH错误。
//4. ReturnLength：一个指向无符号整数的指针，用于返回查询到的系统信息的实际大小。如果缓冲区不足以容纳系统信息，ReturnLength会返回实际需要的大小。




ULONG_PTR QueryModule(PUCHAR ModuleName, PULONG_PTR ModeSize)
{
	//RTL_PROCESS_MODULES Modules;
	PRTL_PROCESS_MODULES pModules = ExAllocatePool(NonPagedPool, sizeof(RTL_PROCESS_MODULES));
	ULONG_PTR relength = 0;

	//pModules用于存储ZwQuerySystemInformation查询到的系统模块信息
	//坑点：ZwQuerySystemInformation的第四个参数ReturnLength第一次申请会失败，因为系统中所有的内核模块的大小都是不确定的，必须在第一次申请以后才会返回真正的大小
	//所以需要判断失败，失败后再根据relength来再次申请内存
	NTSTATUS  st  = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &relength);
	if (!NT_SUCCESS(st))
	{
		ExFreePool(pModules);
		//如果ZwQuerySystemInformation给的第三个参数小于查询的系统信息的大小，会返回STATUS_INFO_LENGTH_MISMATCH错误
		//所以这里要判断下sizeof(RTL_PROCESS_MODULES) 是否 >> 查询系统信息的大小
		if (st != STATUS_INFO_LENGTH_MISMATCH)  //与给的Modules的大小不匹配
		{
			return st;


		}
		
		//这里返回了真正的长度，所以得让第三个参数大一点，防止返回STATUS_INFO_LENGTH_MISMATCH错误
		ULONG totalSize = relength + sizeof(RTL_PROCESS_MODULES);
		pModules = ExAllocatePool(NonPagedPool, totalSize);
		memset(pModules, 0, totalSize);
		st = ZwQuerySystemInformation(SystemModuleInformation, pModules, totalSize, &relength); //再次申请
		if (!NT_SUCCESS(st)&& st != STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pModules);
			return st;
		}



	}
	

	//将传进来的模块名初始化到字符串
	ANSI_STRING String_ModuleName = { 0 };
	RtlInitString(&String_ModuleName, ModuleName);

	//由于段页模式的区分，所以为了兼容所有系统，需要做匹配  10-10-12使用的是ntoskrpla.exe
	//初始化ntoskrnl到字符串
	ANSI_STRING UModentoskrnlName = { 0 };
	RtlInitString(&String_ModuleName, "ntoskrnl.exe");

	//初始化ntoskrpla到字符串
	ANSI_STRING unoskernleName = { 0 };
	RtlInitString(&unoskernleName, "ntoskrpla.exe");



	ULONG_PTR ImageBase = 0;
	ULONG_PTR ImageSize = 0;


	//如果ZwQuerySystemInformation大小匹配成功，则开始遍历传进来的模块名
	if (NT_SUCCESS(st))
	{
		ANSI_STRING unoskernleName = { 0 };

		//对所有段页模式做兼容，不管匹配ntoskrpla还是ntoskrnl，返回各自的模块基地址
		if (RtlCompareString(&String_ModuleName,&UModentoskrnlName,TRUE) == 0 || RtlCompareString(&String_ModuleName, &unoskernleName, TRUE) == 0)
		{
			
			ImageBase = pModules->Modules[0].ImageBase;
			ImageSize = pModules->Modules[0].ImageSize;
		}

		//循环遍历ZwQuerySystemInformation返回的pModules中的值，取出需要的模块的基址
		for (int i =0;i<pModules->NumberOfModules;i++)
		{
			

			//PRTL_PROCESS_MODULE_INFORMATION用于描述进程加载的模块信息。该结构包含以下字段：
			//	- ImageBase：模块在进程空间中的基地址。
			//	- ImageSize：模块大小，以字节为单位。
			//	- ImageName：模块的名称。通常是一个全路径文件名。
			//	- Flags：一个32位的标志值，它可以设置为RTL_PROCESS_MODULE_INFORMATION_FLAG_XXX常量之一，以指示模块的加载状态。
			//	- LoadCount：一个指示模块当前被载入到多少个进程中的计数器。
			//	这个结构体通常被用于内核模块或者安全软件在进程轮询时查询进程加载的模块信息，便于了解该进程的执行环境，或者进行合法性验证或者防护策略的制定。
	
			//使用PRTL_PROCESS_MODULE_INFORMATION定义一个模块结构体，类似于写PE中使用的WIN32 API PIMAGE_FILE_HEADER等，用来存储结构
			PRTL_PROCESS_MODULE_INFORMATION pmod = &pModules->Modules[i];
			PUCHAR baseName = ((PUCHAR)pmod->FullPathName + pmod->OffsetToFileName); //OffsetToFileName+FullPathName才是真正的模块名
			ANSI_STRING anBaseName = { 0 };
			RtlInitString(&anBaseName, baseName);
			//DbgPrintEx(77, 0, "[db]:%Z\r\n", &anBaseName);
			
			if (RtlCompareString(&String_ModuleName, &anBaseName, TRUE) == 0)
			{
				
				ImageBase = pModules->Modules[i].ImageBase;
				ImageSize = pModules->Modules[i].ImageSize;
				break;
			}

		}
	}
	ExFreePool(pModules);

	if (ModeSize) *ModeSize = ImageSize;

	return ImageBase;
}

//查询所有系统模块，火哥代码
static ULONG_PTR QuerySysModule(char* MoudleName, _Out_opt_ ULONG_PTR* module)
{
	RTL_PROCESS_MODULES info;
	ULONG retPro = NULL;
	ULONG_PTR moduleSize = 0;



	NTSTATUS ststas = ZwQuerySystemInformation(SystemModuleInformation, &info, sizeof(info), &retPro);
	char* moduleUper = CharToUper(MoudleName, TRUE);

	if (ststas == STATUS_INFO_LENGTH_MISMATCH)
	{
	
		ULONG len = retPro + sizeof(RTL_PROCESS_MODULES);
		PRTL_PROCESS_MODULES mem = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, len);
		memset(mem, 0, len);
		ststas = ZwQuerySystemInformation(SystemModuleInformation, mem, len, &retPro);

		if (!NT_SUCCESS(ststas))
		{
			ExFreePool(moduleUper);
			ExFreePool(mem);
			return 0;
		}

	

		if (strstr(MoudleName, "ntkrnlpa.exe") || strstr(MoudleName, "ntoskrnl.exe"))
		{
			PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &(mem->Modules[0]);
			*module = ModuleInfo->ImageBase;
			moduleSize = ModuleInfo->ImageSize;
		}
		else
		{
			for (int i = 0; i < mem->NumberOfModules; i++)
			{
				PRTL_PROCESS_MODULE_INFORMATION processModule = &mem->Modules[i];
				CharToUper(processModule->FullPathName, FALSE);
				if (strstr(processModule->FullPathName, moduleUper))
				{
					if (module)
					{
						*module = processModule->ImageBase;

					}

					moduleSize = processModule->ImageSize;

					break;
				}

			}
		}




		ExFreePool(mem);
	}


	ExFreePool(moduleUper);
	return moduleSize;
}


static UCHAR charToHex(UCHAR* ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}



static void initFindCodeStruct(PFindCode findCode, PCHAR code, ULONG_PTR offset, ULONG_PTR lastAddrOffset)
{

	memset(findCode, 0, sizeof(FindCode));

	findCode->lastAddressOffset = lastAddrOffset;
	findCode->offset = offset;

	PCHAR pTemp = code;
	ULONG_PTR i = 0;
	for (i = 0; *pTemp != '\0'; i++)
	{
		if (*pTemp == '*' || *pTemp == '?')
		{
			findCode->code[i] = *pTemp;
			pTemp++;
			continue;
		}

		findCode->code[i] = charToHex(pTemp);
		pTemp += 2;

	}

	findCode->len = i;
}


static ULONG_PTR findAddressByCode(ULONG_PTR beginAddr, ULONG_PTR endAddr, PFindCode  findCode, ULONG numbers)
{
	ULONG64 j = 0;
	LARGE_INTEGER rtna = { 0 };

	for (ULONG_PTR i = beginAddr; i <= endAddr; i++)
	{
		if (!MmIsAddressValid((PVOID)i))
		{
			i = i & (~0xfff) + PAGE_SIZE - 1;
			continue;
		}



		for (j = 0; j < numbers; j++)
		{
			FindCode  fc = findCode[j];
			ULONG_PTR tempAddress = i;

			UCHAR* code = (UCHAR*)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			for (ULONG_PTR k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code + k)))
				{
					isFlags = TRUE;
					break;
				}

				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				if (code[k] != fc.code[k])
				{
					isFlags = TRUE;
					break;
				}
			}

			if (isFlags) break;

		}

		
		if (j == numbers)
		{
			rtna.QuadPart = i;
			rtna.LowPart += findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna.QuadPart;
}

static char* CharToUper(char* wstr, BOOLEAN isAllocateMemory)
{
	char* ret = NULL;

	if (isAllocateMemory)
	{
		int len = strlen(wstr) + 2;
		ret = ExAllocatePool(PagedPool, len);
		memset(ret, 0, len);
		memcpy(ret, wstr, len - 2);
	}
	else
	{
		ret = wstr;
	}

	_strupr(ret);

	return ret;
}



ULONG_PTR searchNtCode(char* code, int offset)
{
	FindCode fs[1] = { 0 };
	initFindCodeStruct(&fs[0], code, 0, offset);


	SIZE_T moduleBase = 0;
	ULONG size = QueryModule("ntoskrnl.exe", &moduleBase);


	ULONG_PTR func = findAddressByCode(moduleBase, size + moduleBase, fs, 1);

	return func;
}

ULONG_PTR searchCode(char* moduleName, char* segmentName, char* code, int offset)
{
	FindCode fs[1] = { 0 };
	initFindCodeStruct(&fs[0], code, 0, offset);
	SIZE_T moduleBase = 0;
	ULONG size = QuerySysModule(moduleName, &moduleBase);

	if (!moduleBase)
	{
		return 0;
	}


	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);

	PIMAGE_SECTION_HEADER pTemp = NULL;

	for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
	{
		char bufName[9] = { 0 };
		memcpy(bufName, pSection->Name, 8);
		if (_stricmp(bufName, segmentName) == 0)
		{
			pTemp = pSection;
			break;
		}
		pSection++;
	}

	if (pTemp)
	{
		moduleBase = pSection->VirtualAddress + moduleBase;
		size = pSection->SizeOfRawData;
	}

	PVOID mem = ExAllocatePool(NonPagedPool, size);
	SIZE_T retSize = 0;
	MmCopyVirtualMemory(IoGetCurrentProcess(), moduleBase, IoGetCurrentProcess(), mem, size, KernelMode, &retSize);

	ULONG_PTR func = findAddressByCode(moduleBase, size + moduleBase, fs, 1);
	ExFreePool(mem);
	return func;
}


NTSTATUS ForceDeleteSys(PWCH path) {

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
		PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
	} OBJECT_ATTRIBUTES;

	//DbgBreakPoint();
	OBJECT_ATTRIBUTES objAttr = { 0 };
	UNICODE_STRING unNamePath = { 0 };
	RtlInitUnicodeString(&unNamePath, path);
	InitializeObjectAttributes(&objAttr, &unNamePath, OBJ_CASE_INSENSITIVE, NULL,NULL);
	NTSTATUS st = ZwDeleteFile(&objAttr);
	if (NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[dbg]:第一层 ZwDeleteFile Successed!!!");
		return st;
	}

	//如果没删掉，通过打开文件再删除
	IO_STATUS_BLOCK iosblock = { 0 };
	HANDLE HFile = NULL;
	st = ZwOpenFile(&HFile, GENERIC_READ, &objAttr, &iosblock, NULL, FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[dbg]:openfile failed ==%x\r\n!!!",st);
		return st;
	}

	//在内核态操作句柄非常不方便，所以将句柄转换成FILE_OBJECT对象再进行删除
	PFILE_OBJECT file = NULL;
	
	st = ObReferenceObjectByHandle(HFile, 0, *IoFileObjectType, KernelMode, &file, NULL);
	ZwClose(HFile);
	if (!NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[dbg]get object file failed!!!");
		return st;
	}
	//如果还是删不掉，是因为文件对象FILE_OBJECT里面有个读和写的权限，必须要置1才能读和写或者删除
	file->DeleteAccess = 1;
	file->SharedDelete = 1;
	file->DeletePending = 0; //如果有人已经在删除它，我们再删除是没用的，所以需要置0
	//上面只是让文件对象具备删除的权限，但是如果有别人正在用的话，还是删不掉的，所以得把当前文件对象正在被使用的引用给置0，才能删掉
	file->SectionObjectPointer->ImageSectionObject = NULL;
	//刷新文件属性
	MmFlushImageSection(file->SectionObjectPointer, MmFlushForDelete);
	
	st = ZwDeleteFile(&objAttr);
	if (!NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[dbg]delete file failed!!!\r\n");

	}
	else
	{
		DbgPrintEx(77, 0, "[dbg]:第二层 ZwDeleteFile Successed!!!\r\n");
	}

}

//修复高版本驱动在低版本操作系统运行驱动的兼容性
void repaircookie(PUCHAR imagebuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imagebuffer;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imagebuffer + pDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	PIMAGE_LOAD_CONFIG_DIRECTORY pconfig = (PIMAGE_LOAD_CONFIG_CODE_INTEGRITY)(pDir->VirtualAddress + imagebuffer);


	*(PULONG_PTR)(pconfig->SecurityCookie) += 10;


}

void DeleteRegKey(PUNICODE_STRING regpath) {

	//RtlAppendUnicodeStringToString  用于将一个Unicode字符串追加到另一个Unicode字符串的末尾。
	//有两个输入参数：DestinationString和SourceString。
	//DestinationString是一个UNICODE_STRING结构体指针，表示要将SourceString追加到的目标Unicode字符串。
	//SourceString也是一个UNICODE_STRING结构体指针，表示要追加到DestinationString末尾的源Unicode字符串。注意，这两个参数中的指针必须都是有效的，并且DestinationString必须已经包含了足够的空间来容纳追加后的Unicode字符串。
	//使用RtlAppendUnicodeStringToString函数后，源Unicode字符串将被追加到目标Unicode字符串的末尾，并将目标Unicode字符串的Length字段更新为新的字符串长度。此外，RtlAppendUnicodeStringToString函数还会自动在目标Unicode字符串的末尾添加一个NULL终止符。

	wchar_t DispalyName[] = L"DispalyName";
	wchar_t ErrorControl[] = L"ErrorControl";
	wchar_t ImagePath[] = L"ImagePath";
	wchar_t Start[] = L"Start";
	wchar_t Type[] = L"Type";
	wchar_t WOW64[] = L"WOW64";

	//RTL_REGISTRY_ABSOLUTE代表绝对路径
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, DispalyName);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, ErrorControl);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, ImagePath);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, Start);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, Type);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, WOW64);
	UNICODE_STRING enumkeyname = { 0 };
	PWCHAR tempkeyname = (PWCHAR)ExAllocatePool(PagedPool, 0x100);
	RtlZeroMemory(tempkeyname, 0x100);
	RtlCopyMemory(tempkeyname, regpath->Buffer, regpath->Length);
	RtlInitUnicodeString(&enumkeyname, tempkeyname);
	enumkeyname.MaximumLength = 0x100;
	RtlAppendUnicodeStringToString(&enumkeyname, L"\\Enum");
	wchar_t zero[] = L"0";
	wchar_t Count[] = L"Count";
	wchar_t NextInstance[] = L"NextInstance";
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumkeyname.Buffer, zero);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumkeyname.Buffer, Count);
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumkeyname.Buffer, NextInstance);
	HANDLE hKey = NULL, hKey2 = NULL;
	OBJECT_ATTRIBUTES objAttr = { 0 };

	//InitializeObjectAttributes参数解释如下：
	//	- pObjectAttributes: 指向需要初始化的OBJECT_ATTRIBUTES结构体的指针。
	//	- pObjectName : 指向UNICODE_STRING结构体的指针，用于指定要打开或创建的对象的名称。如果没有指定名称，则传入NULL。
	//	- dwAttributes : 指定OBJECT_ATTRIBUTES的属性。常用属性包括OBJ_CASE_INSENSITIVE（对象名称不区分大小写）、OBJ_KERNEL_HANDLE（内核对象句柄）等。可以通过按位或运算将多个属性组合起来。
	//	- hRootDirectory : 指定对象的根目录句柄。
	//	- pSecurityDescriptor : 指定安全描述符。
	//	InitializeObjectAttributes函数的作用是初始化OBJECT_ATTRIBUTES结构体，为后续的对象操作打下基础。
	InitializeObjectAttributes(&objAttr, &enumkeyname, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS st = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
	ZwDeleteFile(hKey);
	ZwClose(hKey);
	InitializeObjectAttributes(&objAttr, &regpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	st = ZwOpenKey(&hKey2, KEY_ALL_ACCESS, &objAttr);
	ZwDeleteFile(hKey2);
	ZwClose(hKey2);
}


//MDL映射
//当MDL发生映射时候，因为是分页内存，所以有可能发生磁盘交换，就是PageFiles.sys，所以需要把这块内存锁住

PVOID MapMdl(PVOID buffer, SIZE_T size, MODE mode, PMDL* retPmdl)
{
	//创建MDL映射
	//IoAllocateMdl函数 用于分配描述系统缓冲区的MDL（Memory Descriptor List）。具体而言，它可以将输入的虚拟地址范围映射到物理内存中，并创建一个对应的MDL数据结构
	//	1. Buffer - 要分配的缓冲区的地址。该参数指定了MDL要描述的内存缓冲区的起点。
	//	2. Length - 要分配的缓冲区的大小。该参数指定了MDL要描述的内存缓冲区的长度。
	//	3（给True会蓝屏，通常写FALSE）. SecondaryBuffer - 对于不连续的内存缓冲区，该参数指定一个指向描述第二个内存缓冲区的MDL的指针。对于连续的内存缓冲区，该参数应该为NULL。
	//	4. ChargeQuota - 表示MDL要占用的这个进程的分页池配额的大小。该参数指定了分配MDL使用的分页配额。
	//	5. Irp - 将分配的MDL插入到IRP的结构中。如果要使用I / O请求数据(buffer)接口(iorequestpacket)传递一个MDL给设备对象的话，所用到的就是IRP参数。
	//	6(可选，可不填). MdlFlags - 表示MDL的模式或者行为。该参数中可以包含一系列常量来指定要在MDL中执行的操作。
	//	7(可选，可不填). DriverObject - 允许调用程序在指定的驱动程序环境中运行。该参数指定了应该使用哪个驱动程序对象来申请MDL。
	//	需要注意的是，Irp和DriverObject参数都是可选的，如果不需要对Irp或DriverObject进行操作，可以将其设置为NULL。
	//此外，MdlFlags参数提供了更多操作MDL的选项，例如指定MDL是否可以被修改、指定MDL是否在系统中Mapped等等。
	PMDL pmdl = IoAllocateMdl(buffer, size, FALSE, FALSE, NULL);
	PVOID mapMem = NULL;
	BOOLEAN isExcep = FALSE;
	do
	{

		if (pmdl == NULL) break;
		//使用MmProbeAndLockPages锁住内存的时候，会产生蓝屏问题，微软规定必须使用try_except来写这个函数判断
		//判断如何映射成功，开始使用Try except进行锁页
		__try
		{

			//锁页
			/*MmProbeAndLockPages  将一段虚拟地址指向的物理页面锁定在内存中，并将这些物理页面转换成内核空间使用的MDL（Memory Descriptor List）数据结构。
				通常情况下，一个应用程序只能访问其进程被分配的虚拟地址空间中的页面，而不能直接访问物理页面。MmProbeAndLockPages函数则允许内核空间程序可以访问这些页面。
				该函数的具体作用如下：
				1. 验证输入的地址空间是否属于当前进程，并转换为内核空间可处理的地址。
				2. 检查是否有足够的可用系统资源（如内存和锁对象）。
				3. 锁定虚拟地址页，并返回一个MDL描述这些页的信息。
				4. 通过MDL描述内存页的锁定状态，防止这些页面在锁定之后被换出到磁盘上，从而保证内存中始终存在这些页面。
				由于该函数会直接操作物理内存，所以需要谨慎使用。同时，在使用完毕之后还需要调用MmUnlockPages将这些内存页面解除锁定状态，从而使操作系统可以自由地对这些页面进行处理。*/

			//参数
			//	1.Mdl：描述锁定页面的内存描述符。MDL全称为 Memory Descriptor List，是为内核提供一种描述锁定的内存页面的机制。在函数调用中，MmProbeAndLockPages会使用MDL来描述要锁定的页面，并将页面锁定到内存中。
			//	2. BaseAddress：指向要锁定页面的虚拟地址。这个参数表示要锁定的页面在虚拟内存中的起始地址。
			//	3. Length：要锁定的页面的大小，以字节为单位。这个参数表示要锁定的页面的长度。
			//	4. Operation：表示锁定页面之后的操作。该参数是一个枚举类型，包含如下操作：
			//	- IoReadAccess：标识页面将被用于读取操作。
			//	- IoWriteAccess：标识页面将被用于写操作。
			//	- IoModifyAccess：标识页面将被用于修改操作。


			MmProbeAndLockPages(pmdl, mode, IoReadAccess);//第二个参数代表传递三环还是0环地址，给kernelmode就行
			isExcep = FALSE;
		}
		__except (1)
		{
			isExcep = TRUE;
			break;
		}

		//映射内存
		mapMem = MmMapLockedPages(pmdl, KernelMode);

		if (!mapMem)
		{
			MmUnlockPages(pmdl);
			isExcep = TRUE;
			break;
		}

	} while (0);

	if (isExcep)
	{
		if (pmdl)
		{
			IoFreeMdl(pmdl);

			pmdl = NULL;
		}
	}

	if (pmdl && retPmdl) *retPmdl = pmdl;

	return mapMem;
}

VOID UnMapMdl(PMDL pmdl, PVOID mapMem)
{
	if (pmdl == NULL || mapMem == NULL) return;

	__try
	{
		MmUnmapLockedPages(mapMem, pmdl);

		MmUnlockPages(pmdl);

		IoFreeMdl(pmdl);
	}
	__except (1)
	{
		DbgPrintEx(77, 0, "[db]:MDL Mapping Successed\r\n");
	}

}

//第二种办法，修改Cr0的WP位

PVOID MmMapPhyMem(PVOID buffer, SIZE_T size)
{
	if (buffer == NULL || size == 0) return;
	PHYSICAL_ADDRESS phy = MmGetPhysicalAddress(buffer);
	phy.QuadPart = phy.QuadPart & 0x000FFFFFFFFFFFFFull;
	return MmMapIoSpace(phy, size, MmCached);
}


VOID MmUnMapPhyMem(PVOID buffer, SIZE_T size)
{
	if (buffer == NULL || size == 0) return;
	MmUnmapIoSpace(buffer, size);
}





//隐藏内存
PVOID AlloccateMemory(ULONG size) {


	//我们加载驱动到内存的时候，如果使用ExInsertPoolTag这个函数，那么这个函数会有个内存标记再内存里，无法做到真正隐藏
//所以我们需要使用其他函数比如MmAllocateContiguousMemory将内存申请出来，并且去除内存标记
// 但是MmAllocateContiguousMemory也会调用ExInsertPoolTag，所以通过搜索这个函数的特征码，定位到函数位置的开始return 1，不让他走这个函数
//第一步，去写保护写入硬编码
//打开IDA，搜索ExInsertPoolTag的特征码，使用特征码搜索
//第一种办法：修改当前Cr0寄存器的WP位，去掉写保护，将我们return 1的特征码覆盖到ExInsertPoolTag的地址
//第二种办法：MDL映射，将物理地址重新映射一份虚拟地址，然后再返回给你。则可以写入。但是MDL有可能会申请不成功，会抛出异常，如果当前系统不支持异常，会蓝屏。
//MDL映射缺点解决：MmProbeAndLockPages接管异常
//第二步：申请内存
//第三步：还原修改ExInsertPoolTag覆盖的字节

	PHYSICAL_ADDRESS hphy = { 0 };
	hphy.QuadPart = -1;

	DbgBreakPoint();
	static ULONG_PTR func = 0;
	if (func == 0)
	{
		//判断操作系统版本
		RTL_OSVERSIONINFOEXW version = { 0 };
		RtlGetVersion(&version);
		if (version.dwBuildNumber <= 7601)
		{
#ifdef _X86_
			func = searchCode("ntoskrnl.exe", ".text", "81*****74*81*****77*83**83**83**83**EB", -0x8L);
#else
			func = searchCode("ntoskrnl.exe", ".text", "3D****77*49***49***49***49***EB*49******49******33D2", -0x11L);

#endif
		}
		else
		{
			
			func = searchCode("ntoskrnl.exe", ".text", "4889***894C**555657415441554156415748***4C8BFA458BF133D2498BF0F684******8ADA0FB7EA0F*****", 0x0L);
		}
	}




	if (func)
	{

		//char orgCode[3] = { 0 };
		//memcpy(orgCode, (char*)func, 3);


		char orgCode[3] = { 0 };
		memcpy(orgCode, (char*)func, 3);

		//以下硬编码是return 1，意思让他进到这个ExInsertPoolTag函数之前就return掉，不让他继续调用底下的内存标记函数
			char bufcode[3] =
		{
			0xb0,1,0xc3
		};

		//WIN10
		//B8 01 00 00 00 C3
		//char bufcode[3] =
		//{
		//	0xC2,1,0x00
		//};


		PMDL pmdl = NULL;
		//使用MDL映射去除Cr0 wp位的写保护
		PVOID mapmem = MapMdl(func, 30, KernelMode, &pmdl);
		//PVOID mapmem = MmMapPhyMem(func, 0x30);

		//如果MDL映射成功，将retrun 1覆盖过去
		if (mapmem)
		{
			DbgBreakPoint();
			memcpy((char*)mapmem, bufcode, sizeof(bufcode));
		}

		//wp cr0.wp
		//mdl
			//MmAllocateContiguousMemory 分配内存函数
	//第一个参数是申请的大小
	//第二个参数是物理地址，分配内存的地址范围上限。如果指定为0，则表示没有上限，可以使用所有可用的物理内存地址。

		DbgBreakPoint();
		PVOID mem = MmAllocateContiguousMemory(size, hphy); 


		//还原

		if (mapmem)
		{
			memcpy((char*)mapmem, orgCode, sizeof(orgCode));

			MmUnMapPhyMem(mapmem, 0x30);
			//UnMapMdl(pmdl, mapmem);
		}


		return mem;
	}



	return NULL;
}