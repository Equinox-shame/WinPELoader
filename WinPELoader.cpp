#include <iostream>
#include <Windows.h>
#include "resource.h"
#include "WinPELoader.h"
#define LoadFile
using namespace std;

void MyExitProcess(_In_ UINT uExitCode) {
#ifdef _DEBUG
	printf("[+] 程序已退出，退出代码为 %d\n", uExitCode);
#endif 
	ExitProcess(uExitCode);
}

bool IsPeFile(IN LPVOID BaseAddr) {
	//强转到image_dos_header类型
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddr;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((UINT_PTR)BaseAddr + pDos->e_lfanew);

	if (pDos->e_magic == IMAGE_DOS_SIGNATURE && pNt->Signature == IMAGE_NT_SIGNATURE) {
		return true;
	}

	return false;
}

#ifdef LoadFile
LPVOID LoadPeFromFile(IN LPCSTR PeFileName, OUT PDWORD FileSize) {

	HANDLE hFile = CreateFileA(PeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwSize = GetFileSize(hFile, NULL);
	LPVOID lpbase = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (ReadFile(hFile, lpbase, dwSize, &dwSize, NULL)) {
		*FileSize = dwSize;
		return lpbase;
	}
	return NULL;
}
#endif // LoadFile

LPVOID LoadPE() { // 返回资源文件指针
	HMODULE hModule = GetModuleHandle(NULL);
	HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(IDR_COM1), TEXT("COM"));
	if (hResource == NULL) {
		return NULL;
	}
	HGLOBAL hMemory = LoadResource(hModule, hResource);
	if (hMemory == NULL) {
		return NULL;
	}
	LPVOID lpAddress = LockResource(hMemory);  // 资源文件首地址
	if (lpAddress == NULL) {
		return NULL;
	}
	//DWORD dwSize = SizeofResource(hModule, hResource); // 资源文件大小
	//if (dwSize == 0) {
	//	return;
	//}
	// FreeResource(hMemory); 
#ifdef _DEBUG
	printf("[+] 资源地址: 0x%p\n", lpAddress);
#endif 

	return lpAddress;
}

DWORD __stdcall RVA2VA(IN LPVOID pNt, IN DWORD RVA) {
	return (DWORD)pNt + RVA;
}

PIMAGE_NT_HEADERS GetNTHeader(LPVOID BaseAddr) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)BaseAddr;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	return pNTHeader;
}


LPVOID AllocMemory(PIMAGE_NT_HEADERS pNTHeader) {
	volatile DWORD dwImageSize = pNTHeader->OptionalHeader.SizeOfImage;
	volatile DWORD dwImageBaseAddr = pNTHeader->OptionalHeader.ImageBase;
	LPVOID lpImageBase = VirtualAlloc((LPVOID)dwImageBaseAddr, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (GetLastError() == 0) {
#ifdef _DEBUG
		printf("[+] 正在根据pe的加载基地址 申请内存，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
#endif // _DEBUG
		return lpImageBase;
	}
	else if (GetLastError() && (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0) {
		// 如果无法申请到image推荐的基地址，并且该pe文件支持重定位的话，给他重新申请一个地址
		lpImageBase = VirtualAlloc(NULL, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#ifdef _DEBUG	
		printf("[+] pe的加载基地址不能用，正在重新申请地址中，基地址为 0x%p\n", (LPVOID)dwImageBaseAddr);
#endif // _DEBUG
		return lpImageBase;
	}
	else
	{
		//出错了，只能返回null
		printf("[-] 申请内存失败: 0x%x\n", GetLastError());
		return NULL;
	}
}

void __stdcall CopySectionToMem(IN LPVOID lpPeMem, IN LPVOID lpBaseAddr, IN PIMAGE_NT_HEADERS pNt) {
	DWORD dwNumOfSection = pNt->FileHeader.NumberOfSections;
	DWORD dwSectionAlignment = pNt->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSecHed = (PIMAGE_SECTION_HEADER)((UINT_PTR)pNt + sizeof(IMAGE_NT_HEADERS));

	for (DWORD index = 0; index < dwNumOfSection; index++)
	{
		DWORD dwRva = pSecHed->VirtualAddress;
		DWORD dwFOA = pSecHed->PointerToRawData;
		DWORD dwSize = pSecHed->SizeOfRawData;
		//拷贝源是文件对齐的foa
		LPVOID SecDataSrc = (LPVOID)((UINT_PTR)lpBaseAddr + (UINT_PTR)dwFOA);
		//目的地址是RV
		LPVOID SecDataDst = (LPVOID)RVA2VA(lpPeMem, dwRva);
		//开始拷贝
		RtlCopyMemory(SecDataDst, SecDataSrc, dwSize);
#ifdef _DEBUG
		printf("[+] 正在拷贝 %s section 到内存的 0x%p, 大小为 %d\n", pSecHed->Name, SecDataDst, dwSize);
#endif // _DEBUG
		pSecHed = (PIMAGE_SECTION_HEADER)((UINT_PTR)pSecHed + sizeof(IMAGE_SECTION_HEADER));
	}
	return;
}

void RepairImportTable(PIMAGE_NT_HEADERS pNtHeader, LPVOID lpImageBase) {
	FARPROC procAddr;
	DWORD dwImportTableRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwImportTableRVA == 0) {
		//如果rva等于0的话，则说明没有导入表，不需要处理导入表
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportTab = (PIMAGE_IMPORT_DESCRIPTOR)RVA2VA(lpImageBase, dwImportTableRVA);
	while (pImportTab->OriginalFirstThunk && pImportTab->FirstThunk) {
		char* DllName = (char*)(RVA2VA(lpImageBase, pImportTab->Name));
#ifdef _DEBUG		
		printf("[+] 正在修正导入库 %s\n", DllName);
#endif
		PDWORD FirstTunkVA = (PDWORD)RVA2VA(lpImageBase, pImportTab->FirstThunk);
		HMODULE hModle = LoadLibraryA(DllName);
		while (*FirstTunkVA != 0) {
			PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(RVA2VA(lpImageBase, *FirstTunkVA));
			if (strcmp(pImportName->Name, "ExitProcess") == 0) { // 可以设置为Hook函数
				procAddr = (FARPROC)&MyExitProcess;
			}
			else
			{
				procAddr = GetProcAddress(hModle, pImportName->Name);
			}
			*FirstTunkVA = (DWORD)procAddr;
			FirstTunkVA = (DWORD*)((DWORD)FirstTunkVA + sizeof(DWORD));
#ifdef _DEBUG
			printf("[+] 正在修正 %s 的导入地址， 修正后的函数地址为 0x%p\n", pImportName->Name, procAddr);
#endif // _DEBUG
		}
#ifdef _DEBUG
		printf("\n");
#endif // _DEBUG
		pImportTab = (IMAGE_IMPORT_DESCRIPTOR*)((UINT_PTR)pImportTab + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return;
}

void RepairRelocationTable(PIMAGE_NT_HEADERS pNtHeader, LPVOID lpImageBase) {
	DWORD dwRelocTableRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (dwRelocTableRVA == 0) {
		//如果rva等于0的话，则说明没有重定位表，不需要处理重定位表
		return;
	}
	PIMAGE_BASE_RELOCATION pRelocTab = (PIMAGE_BASE_RELOCATION)RVA2VA(lpImageBase, dwRelocTableRVA);
	DWORD dwRelocSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size; // 重定位表的大小
	DWORD dwDelta = (DWORD)((UINT_PTR)lpImageBase - pNtHeader->OptionalHeader.ImageBase); // 基址的偏移量
#ifdef _DEBUG
	printf("[+] 发现重定位表，开始修正...\n");
#endif
	while (dwRelocSize > 0) {
		DWORD dwRelocCount = (pRelocTab->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); // 重定位项的数量
#ifdef _DEBUG
		printf("[+] 发现 %d块需要重定位的地址信息\n", dwRelocCount);
#endif	
		PWORD pRelocItem = (PWORD)((UINT_PTR)pRelocTab + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD index = 0; index < dwRelocCount; index++) {
			if (((*pRelocItem) >> 12) == IMAGE_REL_BASED_HIGHLOW) {
				DWORD* dwRelocAddr = (DWORD*)((UINT_PTR)lpImageBase + (pRelocTab->VirtualAddress + ((*pRelocItem) & 0x0fff)));
				*dwRelocAddr += dwDelta;
#ifdef _DEBUG
				printf("[+] 修正后的地址为 0x%p\t\n", dwRelocAddr);
#endif
			}
			pRelocItem = (PWORD)((UINT_PTR)pRelocItem + sizeof(WORD));
		}
		dwRelocSize -= pRelocTab->SizeOfBlock;
		pRelocTab = (PIMAGE_BASE_RELOCATION)((UINT_PTR)pRelocTab + pRelocTab->SizeOfBlock);
	}
	return;
}

void Loader(char* FileName) {
#ifndef LoadFile
	LPVOID PEBase = LoadPE();
	if (PEBase == NULL) {
		return;
	}
#else
		DWORD dwFileSize = 0;
		LPVOID PEBase = LoadPeFromFile((LPCSTR)FileName, &dwFileSize);
		if (PEBase == NULL) {
			printf("[-] 读取文件失败\n");
			return;
		}
		if (!IsPeFile(PEBase)) {
			printf("[-] 文件不是pe文件\n");
			return;
		}

#endif

	PIMAGE_NT_HEADERS pNTHeader = GetNTHeader(PEBase); // 获取pe的NT头 
	if (pNTHeader == NULL) {
		return;
	}
	LPVOID lpImageBase = AllocMemory(pNTHeader); // 根据pe的加载基地址 申请内存
	if (lpImageBase == NULL) {
		return;
	}
	// 申请内存成功，开始填充pe文件
	RtlCopyMemory(lpImageBase, PEBase, pNTHeader->OptionalHeader.SizeOfHeaders); // 拷贝头部
	CopySectionToMem(lpImageBase, PEBase, pNTHeader); // 拷贝节区

	// 修复导入表
	RepairImportTable(pNTHeader, lpImageBase);

	// 修复重定位表
	RepairRelocationTable(pNTHeader, lpImageBase);

	// 获取程序入口点
	DWORD dwEntryPoint = RVA2VA(lpImageBase, pNTHeader->OptionalHeader.AddressOfEntryPoint);
#ifdef _DEBUG
	printf("[+] 程序的入口点为: 0x%p \n", dwEntryPoint);
	printf("----------------- 程序输出 -----------------\n");
#endif // _DEBUG

	__asm {
		jmp dwEntryPoint
	}
}



int main(int argc, char** argv) {
#ifndef LoadFile
	Loader(NULL);
#else
	if (argc != 2) {
		printf("[-] 参数错误\n");
		printf("[+] 使用方法: %s <FileName>\n", argv[0]);
		return 0;
	}
	char* FileName = argv[1];
	Loader(FileName);
#endif // !LoadFile
	return 0;
}