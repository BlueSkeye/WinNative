#pragma once

#ifndef _NTPEIMAGE_
#define _NTPEIMAGE_

#include "NtCommonDefs.h"

extern "C" {

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

	typedef struct _IMAGE_DATA_DIRECTORY {
		DWORD VirtualAddress;
		DWORD Size;
	} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	typedef struct _IMAGE_FILE_HEADER {
		WORD  Machine;
		WORD  NumberOfSections;
		DWORD TimeDateStamp;
		DWORD PointerToSymbolTable;
		DWORD NumberOfSymbols;
		WORD  SizeOfOptionalHeader;
		WORD  Characteristics;
	} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD Magic;
		BYTE MajorLinkerVersion;
		BYTE MinorLinkerVersion;
		DWORD SizeOfCode;
		DWORD SizeOfInitializedData;
		DWORD SizeOfUninitializedData;
		DWORD AddressOfEntryPoint;
		DWORD BaseOfCode;
		ULONGLONG ImageBase;
		DWORD SectionAlignment;
		DWORD FileAlignment;
		WORD MajorOperatingSystemVersion;
		WORD MinorOperatingSystemVersion;
		WORD MajorImageVersion;
		WORD MinorImageVersion;
		WORD MajorSubsystemVersion;
		WORD MinorSubsystemVersion;
		DWORD Win32VersionValue;
		DWORD SizeOfImage;
		DWORD SizeOfHeaders;
		DWORD CheckSum;
		WORD Subsystem;
		WORD DllCharacteristics;
		ULONGLONG SizeOfStackReserve;
		ULONGLONG SizeOfStackCommit;
		ULONGLONG SizeOfHeapReserve;
		ULONGLONG SizeOfHeapCommit;
		DWORD LoaderFlags;
		DWORD NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
	typedef struct _IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
	typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

	// From winnt.h
	typedef struct _IMAGE_RESOURCE_DIRECTORY {
		DWORD Characteristics;
		DWORD TimeDateStamp;
		WORD MajorVersion;
		WORD MinorVersion;
		WORD NumberOfNamedEntries;
		WORD NumberOfIdEntries;
		//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
	} IMAGE_RESOURCE_DIRECTORY, * PIMAGE_RESOURCE_DIRECTORY;

	// From ntimage.h
	typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
		ULONG OffsetToData;
		ULONG Size;
		ULONG CodePage;
		ULONG Reserved;
	} IMAGE_RESOURCE_DATA_ENTRY, * PIMAGE_RESOURCE_DATA_ENTRY;

	// From winnt.h
	typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
		WORD    Length;
		CHAR    NameString[1];
	} IMAGE_RESOURCE_DIRECTORY_STRING, * PIMAGE_RESOURCE_DIRECTORY_STRING;

	typedef struct _RTL_BALANCED_NODE RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___b_a_l_a_n_c_e_d___n_o_d_e.html
	struct _RTL_BALANCED_NODE {
		union {
			PRTL_BALANCED_NODE Children[2];
			struct {
				PRTL_BALANCED_NODE Left;
				PRTL_BALANCED_NODE Right;
			} DUMMYSTRUCTNAME;
		};
		union {
			UCHAR Red : 1;
			UCHAR Balance : 2;
			ULONG_PTR ParentValue;
		} DUMMYUNIONNAME;
	};

}

#endif // _NTPEIMAGE_