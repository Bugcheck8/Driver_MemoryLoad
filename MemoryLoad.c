#include "MemoryLoad.h"


PVOID NTAPI FindExportedRoutineByName(PVOID ImageBase, PCHAR funcName)
{

	typedef PVOID(NTAPI* FindExportedRoutineByNameProc)(PVOID ImageBase, PCHAR funcName);

	static FindExportedRoutineByNameProc FindExportedRoutineByNameFunc = NULL;

	if (FindExportedRoutineByNameFunc)
	{
		return FindExportedRoutineByNameFunc(ImageBase, funcName);
	}

	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(&version);




	//7600 7601
	if (version.dwBuildNumber <= 7601)
	{
		//UNICODE_STRING uName = {0};
		//RtlInitUnicodeString(&uName, L"MmGetSystemRoutineAddress");
		//MmGetSystemRoutineAddress(&uName);


		wchar_t wa_MmGetSystemRoutineAddress[] = { 0xE3AE, 0xE38E, 0xE3A4, 0xE386, 0xE397, 0xE3B0, 0xE39A, 0xE390, 0xE397, 0xE386, 0xE38E, 0xE3B1, 0xE38C, 0xE396, 0xE397, 0xE38A, 0xE38D, 0xE386, 0xE3A2, 0xE387, 0xE387, 0xE391, 0xE386, 0xE390, 0xE390, 0xE3E3, 0xE3E3 };

		for (int i = 0; i < 27; i++)
		{
			wa_MmGetSystemRoutineAddress[i] ^= 0x6D6D;
			wa_MmGetSystemRoutineAddress[i] ^= 0x8E8E;
		};

		UNICODE_STRING unFuncNameMmGetSystemRoutineAddress = { 0 };
		RtlInitUnicodeString(&unFuncNameMmGetSystemRoutineAddress, wa_MmGetSystemRoutineAddress);
		PUCHAR funcMmGetSystemRoutineAddress = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameMmGetSystemRoutineAddress);

#ifdef _X86_
		for (int i = 0; i < 0x100; i++)
		{
			if (funcMmGetSystemRoutineAddress[i] == 0xe8 && funcMmGetSystemRoutineAddress[i + 5] == 0x8b)
			{
				LONG offset = *(PLONG)(funcMmGetSystemRoutineAddress + i + 1);
				ULONG next = (ULONG)(funcMmGetSystemRoutineAddress + i + 5);
				FindExportedRoutineByNameFunc = (FindExportedRoutineByNameProc)(offset + next);
				break;
			}
		}
#else
		for (int i = 0; i < 0x100; i++)
		{
			if (funcMmGetSystemRoutineAddress[i] == 0xe8 && funcMmGetSystemRoutineAddress[i + 5] == 0x48)
			{
				LONG64 offset = *(PLONG)(funcMmGetSystemRoutineAddress + i + 1);
				ULONG64 next = (ULONG64)(funcMmGetSystemRoutineAddress + i + 5);
				FindExportedRoutineByNameFunc = (FindExportedRoutineByNameProc)(offset + next);
				break;
			}
		}
#endif


	}
	else
	{
		wchar_t wa_RtlFindExportedRoutineByName[] = { 0xE3B1, 0xE397, 0xE38F, 0xE3A5, 0xE38A, 0xE38D, 0xE387, 0xE3A6, 0xE39B, 0xE393, 0xE38C, 0xE391, 0xE397, 0xE386, 0xE387, 0xE3B1, 0xE38C, 0xE396, 0xE397, 0xE38A, 0xE38D, 0xE386, 0xE3A1, 0xE39A, 0xE3AD, 0xE382, 0xE38E, 0xE386, 0xE3E3, 0xE3E3 };

		for (int i = 0; i < 30; i++)
		{
			wa_RtlFindExportedRoutineByName[i] ^= 0x6D6D;
			wa_RtlFindExportedRoutineByName[i] ^= 0x8E8E;
		};

		UNICODE_STRING unFuncNameRtlFindExportedRoutineByName = { 0 };
		RtlInitUnicodeString(&unFuncNameRtlFindExportedRoutineByName, wa_RtlFindExportedRoutineByName);
		PUCHAR funcRtlFindExportedRoutineByName = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameRtlFindExportedRoutineByName);
		FindExportedRoutineByNameFunc = (FindExportedRoutineByNameProc)funcRtlFindExportedRoutineByName;
	}

	if (FindExportedRoutineByNameFunc)
	{
		return FindExportedRoutineByNameFunc(ImageBase, funcName);
	}

	return NULL;
}

void ReImport(PUCHAR imageBuffer)
{
	//DbgBreakPoint();

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);

	PIMAGE_DATA_DIRECTORY pDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!pDir->VirtualAddress) return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pDir->VirtualAddress + imageBuffer);

	for (; pImportDesc->OriginalFirstThunk != 0 && pImportDesc->FirstThunk != 0; pImportDesc++)
	{
		char* pModuleName = (char*)(pImportDesc->Name + imageBuffer);

		ULONG_PTR module = QueryModule(pModuleName, NULL);

		if (!module) continue;

		PIMAGE_THUNK_DATA pNames = (PIMAGE_THUNK_DATA)(pImportDesc->OriginalFirstThunk + imageBuffer);

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImportDesc->FirstThunk + imageBuffer);

		for (; pThunk->u1.ForwarderString; ++pThunk)
		{
		
			if ((pThunk->u1.Ordinal >> 31) == 1)
			{

			}
			else
			{
				PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + imageBuffer);

				char* functionName = byName->Name;

				PVOID function = FindExportedRoutineByName(module, functionName);

				DbgPrintEx(77, 0, "[db]:%s==>%x\r\n", functionName, function);

				if (function != NULL)
				{
					pThunk->u1.Function = function;
				}
			}
		}

	}





}

//修复重定位表
void Relocation(PUCHAR imageBuffer)
{
	typedef struct _RelocImage
	{
		USHORT offset : 12;
		USHORT type : 4;
	}RelocImage, * PRelocImage;

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);

	PIMAGE_DATA_DIRECTORY pDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (!pDir->Size) return;

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(pDir->VirtualAddress + imageBuffer);

	while (pBaseRelocation->SizeOfBlock && pBaseRelocation->VirtualAddress)
	{

		PRelocImage pRimage = (PRelocImage)((PUCHAR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		ULONG pRImageCount = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		
		for (int i = 0; i < pRImageCount; i++)
		{

			//每一个前3字节==3的时候是需要修改的地方
			if (pRimage[i].type == IMAGE_REL_BASED_HIGHLOW)
			{
				PULONG address = (PULONG)(pRimage[i].offset + pBaseRelocation->VirtualAddress + imageBuffer);
				DbgPrintEx(77, 0, "[dbg]:需要修改的地址 == %x\r\n", *address);
				ULONG xValue = *address;
				*address = xValue - pNts->OptionalHeader.ImageBase + (ULONG_PTR)imageBuffer;
				//xValue - pNts-
			}
			else if (pRimage[i].type == IMAGE_REL_BASED_DIR64)
			{
				PULONG64 address = (PULONG64)(pRimage[i].offset + pBaseRelocation->VirtualAddress + imageBuffer);
				DbgPrintEx(77, 0, "[dbg]:需要修改的地址：%llx\r\n", *address);
				ULONG64 xValue = *address;
				*address = xValue - pNts->OptionalHeader.ImageBase + (ULONG64)imageBuffer;
			}
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	//DbgBreakPoint();

	pNts->OptionalHeader.ImageBase = (ULONG_PTR)imageBuffer;

}
//内存加载sys主模块

BOOLEAN MemLoadLibrary(PUCHAR buffer, int size)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);

	ULONG sizeofImage = pNts->OptionalHeader.SizeOfImage;

	//PUCHAR image = ExAllocatePool(NonPagedPool, sizeofImage);
	//DbgBreakPoint();
	PUCHAR image = AlloccateMemory(sizeofImage);
	if (image == NULL) return FALSE;

	memset(image, 0, sizeofImage);



	memcpy(image, buffer, pNts->OptionalHeader.SizeOfHeaders);


	PIMAGE_SECTION_HEADER pFistSection = IMAGE_FIRST_SECTION(pNts);

	for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
	{

		memcpy(image + pFistSection[i].VirtualAddress, buffer + pFistSection[i].PointerToRawData, pFistSection[i].SizeOfRawData);
	}


	//DbgBreakPoint();
	Relocation(image);

	//DbgBreakPoint();
	ReImport(image);
	
	//DbgBreakPoint();
	repaircookie(image);


	PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)image;

	PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(image + pDosImage->e_lfanew);



	PDRIVER_INITIALIZE oep = (PDRIVER_INITIALIZE)(pNtsImage->OptionalHeader.AddressOfEntryPoint + image);

	oep(image, image);
	


}


