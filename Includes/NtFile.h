#pragma once

#ifndef _NTFILE_
#define _NTFILE_

#include "NtCommonDefs.h"
#include "NtAccessRights.h"

#ifdef __cplusplus
extern "C" {
#endif

	// NO UNRESOLVED FUNCTIONS

	// Forward declarations
	typedef struct _IO_STATUS_BLOCK *PIO_STATUS_BLOCK;

	// Structures and enumerations declarations
	// https://github.com/winsiderss/systeminformer/blob/dd76af8d5f64ca6c5436d6fc86890f2ab90e17d7/phnt/include/ntioapi.h#L2109C1-L2115C76
	typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS {
		DirectoryNotifyInformation = 1, // FILE_NOTIFY_INFORMATION
		DirectoryNotifyExtendedInformation, // FILE_NOTIFY_EXTENDED_INFORMATION
		DirectoryNotifyFullInformation, // FILE_NOTIFY_FULL_INFORMATION // since 22H2
		DirectoryNotifyMaximumInformation
	} DIRECTORY_NOTIFY_INFORMATION_CLASS, * PDIRECTORY_NOTIFY_INFORMATION_CLASS;

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information
	typedef struct _FILE_BASIC_INFORMATION {
		LARGE_INTEGER CreationTime;
		LARGE_INTEGER LastAccessTime;
		LARGE_INTEGER LastWriteTime;
		LARGE_INTEGER ChangeTime;
		ULONG         FileAttributes;
	} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
	typedef enum _FILE_INFORMATION_CLASS {
		FileDirectoryInformation = 1,
		FileFullDirectoryInformation = 2,
		FileBothDirectoryInformation = 3,
		FileBasicInformation = 4,
		FileStandardInformation = 5,
		FileInternalInformation = 6,
		FileEaInformation = 7,
		FileAccessInformation = 8,
		FileNameInformation = 9,
		FileRenameInformation = 10,
		FileLinkInformation = 11,
		FileNamesInformation = 12,
		FileDispositionInformation = 13,
		FilePositionInformation = 14,
		FileFullEaInformation = 15,
		FileModeInformation = 16,
		FileAlignmentInformation = 17,
		FileAllInformation = 18,
		FileAllocationInformation = 19,
		FileEndOfFileInformation = 20,
		FileAlternateNameInformation = 21,
		FileStreamInformation = 22,
		FilePipeInformation = 23,
		FilePipeLocalInformation = 24,
		FilePipeRemoteInformation = 25,
		FileMailslotQueryInformation = 26,
		FileMailslotSetInformation = 27,
		FileCompressionInformation = 28,
		FileObjectIdInformation = 29,
		FileCompletionInformation = 30,
		FileMoveClusterInformation = 31,
		FileQuotaInformation = 32,
		FileReparsePointInformation = 33,
		FileNetworkOpenInformation = 34,
		FileAttributeTagInformation = 35,
		FileTrackingInformation = 36,
		FileIdBothDirectoryInformation = 37,
		FileIdFullDirectoryInformation = 38,
		FileValidDataLengthInformation = 39,
		FileShortNameInformation = 40,
		FileIoCompletionNotificationInformation = 41,
		FileIoStatusBlockRangeInformation = 42,
		FileIoPriorityHintInformation = 43,
		FileSfioReserveInformation = 44,
		FileSfioVolumeInformation = 45,
		FileHardLinkInformation = 46,
		FileProcessIdsUsingFileInformation = 47,
		FileNormalizedNameInformation = 48,
		FileNetworkPhysicalNameInformation = 49,
		FileIdGlobalTxDirectoryInformation = 50,
		FileIsRemoteDeviceInformation = 51,
		FileUnusedInformation = 52,
		FileNumaNodeInformation = 53,
		FileStandardLinkInformation = 54,
		FileRemoteProtocolInformation = 55,
		FileRenameInformationBypassAccessCheck = 56,
		FileLinkInformationBypassAccessCheck = 57,
		FileVolumeNameInformation = 58,
		FileIdInformation = 59,
		FileIdExtdDirectoryInformation = 60,
		FileReplaceCompletionInformation = 61,
		FileHardLinkFullIdInformation = 62,
		FileIdExtdBothDirectoryInformation = 63,
		FileDispositionInformationEx = 64,
		FileRenameInformationEx = 65,
		FileRenameInformationExBypassAccessCheck = 66,
		FileDesiredStorageClassInformation = 67,
		FileStatInformation = 68,
		FileMemoryPartitionInformation = 69,
		FileStatLxInformation = 70,
		FileCaseSensitiveInformation = 71,
		FileLinkInformationEx = 72,
		FileLinkInformationExBypassAccessCheck = 73,
		FileStorageReserveIdInformation = 74,
		FileCaseSensitiveInformationForceAccessCheck = 75,
		FileKnownFolderInformation = 76,
		FileStatBasicInformation = 77,
		FileId64ExtdDirectoryInformation = 78,
		FileId64ExtdBothDirectoryInformation = 79,
		FileIdAllExtdDirectoryInformation = 80,
		FileIdAllExtdBothDirectoryInformation = 81,
		FileStreamReservationInformation,
		FileMupProviderInfo,
		FileMaximumInformation
	} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_network_open_information
	typedef struct _FILE_NETWORK_OPEN_INFORMATION {
		LARGE_INTEGER CreationTime;
		LARGE_INTEGER LastAccessTime;
		LARGE_INTEGER LastWriteTime;
		LARGE_INTEGER ChangeTime;
		LARGE_INTEGER AllocationSize;
		LARGE_INTEGER EndOfFile;
		ULONG         FileAttributes;
	} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_segment_element
	typedef union _FILE_SEGMENT_ELEMENT {
		PVOID64   Buffer;
		ULONGLONG Alignment;
	} FILE_SEGMENT_ELEMENT, * PFILE_SEGMENT_ELEMENT;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_fsinfoclass
	typedef enum _FSINFOCLASS {
		FileFsVolumeInformation,
		FileFsLabelInformation,
		FileFsSizeInformation,
		FileFsDeviceInformation,
		FileFsAttributeInformation,
		FileFsControlInformation,
		FileFsFullSizeInformation,
		FileFsObjectIdInformation,
		FileFsDriverPathInformation,
		FileFsVolumeFlagsInformation,
		FileFsSectorSizeInformation,
		FileFsDataCopyInformation,
		FileFsMetadataSizeInformation,
		FileFsFullSizeInformationEx,
		FileFsGuidInformation,
		FileFsMaximumInformation
	} FS_INFORMATION_CLASS, * PFS_INFORMATION_CLASS;

	typedef VOID (NTAPI* PIO_APC_ROUTINE) (
		_In_ PVOID ApcContext,
		_In_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG Reserved);

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID    Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK;

	typedef struct _OVERLAPPED {
		ULONG_PTR Internal;
		ULONG_PTR InternalHigh;
		union {
			struct {
				DWORD Offset;
				DWORD OffsetHigh;
			} DUMMYSTRUCTNAME;
			PVOID Pointer;
		} DUMMYUNIONNAME;
		HANDLE    hEvent;
	} OVERLAPPED, * LPOVERLAPPED;
	
	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	typedef struct _RTLP_CURDIR_REF {
		LONG ReferenceCount;
		HANDLE DirectoryHandle;
	} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	typedef enum _RTL_PATH_TYPE RTL_PATH_TYPE, * PRTL_PATH_TYPE;
	enum _RTL_PATH_TYPE {
		RtlPathTypeUnknown,
		RtlPathTypeUncAbsolute,     // "\\\\server\\share\\folder\\file.txt
		RtlPathTypeDriveAbsolute,   // "C:\\folder\\file.txt"
		RtlPathTypeDriveRelative,   // "C:folder\\file.txt"
		RtlPathTypeRooted,          // "\\folder\\file.txt"
		RtlPathTypeRelative,        // "folder\\file.txt"
		RtlPathTypeLocalDevice,     // "\\\\.\\PhysicalDrive0"
		RtlPathTypeRootLocalDevice  // "\\\\?\\C:\\folder\\file.txt"
	};

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	typedef struct _RTL_RELATIVE_NAME_U {
		UNICODE_STRING RelativeName;
		HANDLE ContainingDirectory;
		PRTLP_CURDIR_REF CurDirRef;
	} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

	//https://ntdoc.m417z.com/ldrgetfilenamefromloadasdatatable
	//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html
	NTSYSAPI NTSTATUS NTAPI LdrGetFileNameFromLoadAsDataTable(
		_In_ PVOID Module,
		_Out_ PVOID* pFileNamePrt);

	// https://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/rtlexec/openimagefileoptionskey.htm
	// https://doxygen.reactos.org/d8/d6b/ldrinit_8c.html
	NTSYSAPI NTSTATUS NTAPI LdrOpenImageFileOptionsKey(
		_In_ PUNICODE_STRING lpImageFile,
		_In_ BOOLEAN bWow64,
		_Out_ PHANDLE phKey);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/ldrinit/queryimagefileexecutionoptions.htm
	// https://doxygen.reactos.org/d8/d6b/ldrinit_8c.html#a27234a85c34ab9698ba3b7d7439ca69b
	NTSYSAPI NTSTATUS NTAPI LdrQueryImageFileExecutionOptions(
		_In_ PUNICODE_STRING lpImageFile,
		_In_ PCWSTR lpszOption,
		_In_ ULONG dwType,
		_Out_ PVOID lpData,
		_In_ ULONG cbData,
		_Out_opt_ PULONG lpcbData);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/rtlexec/queryimagefileexecutionoptionsex.htm
	// https://doxygen.reactos.org/d8/d6b/ldrinit_8c.html#a27234a85c34ab9698ba3b7d7439ca69b
	NTSYSAPI NTSTATUS NTAPI LdrQueryImageFileExecutionOptionsEx(
		_In_ PUNICODE_STRING lpImageFile,
		_In_ PCWSTR lpszOption,
		_In_ ULONG dwType,
		_Out_ PVOID lpData,
		_In_ ULONG cbData,
		_Out_opt_ PULONG lpcbData,
		_In_ BOOLEAN bWow64);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/rtlexec/queryimagefilekeyoption.htm
	NTSYSAPI NTSTATUS NTAPI LdrQueryImageFileKeyOption(
		HANDLE hKey,
		PCWSTR lpszOption,
		ULONG dwType,
		PVOID lpData,
		ULONG cbData,
		PULONG lpcbData);

	// https://processhacker.sourceforge.io/doc/ntmmapi_8h.html
	NTSYSCALLAPI NTSTATUS NTAPI NtAreMappedFilesTheSame(
		_In_ PVOID File1MappedAsAnImage,
		_In_ PVOID File2MappedAsFile);
	//ZwAreMappedFilesTheSame

	// https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
	// https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-i-o-ports
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntioapi.h#L2361
	NTSYSCALLAPI NTSTATUS NTAPI NtAssociateWaitCompletionPacket(
		_In_ HANDLE WaitCompletionPacketHandle,
		_In_ HANDLE IoCompletionHandle,
		_In_ HANDLE TargetObjectHandle,
		_In_opt_ PVOID KeyContext,
		_In_opt_ PVOID ApcContext,
		_In_ NTSTATUS IoStatus,
		_In_ ULONG_PTR IoStatusInformation,
		_Out_opt_ PBOOLEAN AlreadySignaled);
	//ZwAssociateWaitCompletionPacket

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/nt-cancel-io-file
	NTSYSCALLAPI BOOL NTAPI NtCancelIoFile(
		_In_ HANDLE hFile);
	//ZwCancelIoFile

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/nt-cancel-io-file-ex
	NTSYSCALLAPI BOOL NTAPI NtCancelIoFileEx(
		_In_     HANDLE       hFile,
		_In_opt_ LPOVERLAPPED lpOverlapped
	);
	//ZwCancelIoFileEx

	//https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(
		_In_ HANDLE ThreadHandle,
		_In_opt_ PIO_STATUS_BLOCK IoStatusBlockIn,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock);
	//ZwCancelSynchronousIoFile

	//https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCancelWaitCompletionPacket(
		_In_ HANDLE CompletionHandle,
		_In_ BOOLEAN Flag);
	//ZwCancelWaitCompletionPacket

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcopyfilechunk
	NTSYSCALLAPI NTSTATUS NtCopyFileChunk(
		_In_ HANDLE SourceHandle,
		_In_ HANDLE DestHandle,
		_In_opt_ HANDLE Event,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG Length,
		_In_ PLARGE_INTEGER SourceOffset,
		_In_ PLARGE_INTEGER DestOffset,
		_In_opt_ PULONG SourceKey,
		_In_opt_ PULONG DestKey,
		_In_ ULONG Flags);
	//ZwCopyFileChunk
	
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
	// https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength);
	// ZwCreateFile

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
	NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(
		_Out_ PHANDLE IoHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG NumberOfConcurrentThreads);
	//ZwCreateIoCompletion

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtCreateMailslotFile(
		_Out_ PHANDLE             MailslotFileHandle,
		_In_ ACCESS_MASK          DesiredAccess,
		_In_ POBJECT_ATTRIBUTES   ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK    IoStatusBlock,
		_In_ ULONG                CreateOptions,
		_In_ ULONG                MailslotQuota,
		_In_ ULONG                MaxMessageSize,
		_In_ PLARGE_INTEGER       ReadTimeOut);
	//ZwCreateMailslotFile

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/nt-create-named-pipe-file
	NTSYSCALLAPI NTSTATUS NtCreateNamedPipeFile(
		_Out_ PHANDLE FileHandle,
		_In_ ULONG DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_ ULONG NamedPipeType,
		_In_ ULONG ReadMode,
		_In_ ULONG CompletionMode,
		_In_ ULONG MaximumInstances,
		_In_ ULONG InboundQuota,
		_In_ ULONG OutboundQuota,
		_In_opt_ PLARGE_INTEGER DefaultTimeout);
	//ZwCreateNamedPipeFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateWaitCompletionPacket(
		_Out_ PHANDLE WaitCompletionPacketHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwCreateWaitCompletionPacket

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwdeletefile
	NTSYSCALLAPI NTSTATUS NTAPI NtDeleteFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwDeleteFile

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile
	// See winternl.h
	NTSYSCALLAPI NTSTATUS NTAPI NtDeviceIoControlFile(
		_In_  HANDLE           FileHandle,
		_In_  HANDLE           Event,
		_In_  PIO_APC_ROUTINE  ApcRoutine,
		_In_  PVOID            ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_  ULONG            IoControlCode,
		_In_  PVOID            InputBuffer,
		_In_  ULONG            InputBufferLength,
		_Out_ PVOID            OutputBuffer,
		_In_  ULONG            OutputBufferLength);
	// ZwDeviceIoControlFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtDeviceIoControlFile(
		_In_ HANDLE FileHandle,
		_In_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG IoControlCode,
		_In_ PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_ PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength);
	// ZwDeviceIoControlFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfile
	NTSYSCALLAPI NTSTATUS NtFlushBuffersFileEx(
		_In_ HANDLE FileHandle,
		_In_ ULONG Flags,
		_In_ PVOID Parameters,
		_In_ ULONG ParametersSize,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock);
	//ZwFlushBuffersFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwfscontrolfile
	NTSYSAPI NTSTATUS NtFsControlFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG FsControlCode,
		_In_opt_ PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_opt_ PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength);
	//ZwFsControlFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtInitializeNlsFiles(
		_Out_ PPVOID BaseAddress,
		_Out_ PLCID DefaultLocaleId,
		_Out_ PLARGE_INTEGER DefaultCasingTableSize);
	//ZwInitializeNlsFiles

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntlockfile
	NTSYSCALLAPI NTSTATUS NtLockFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PLARGE_INTEGER   ByteOffset,
		_In_ PLARGE_INTEGER   Length,
		_In_ ULONG            Key,
		_In_ BOOLEAN          FailImmediately,
		_In_ BOOLEAN          ExclusiveLock);
	//ZwLockFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntlockfile
	NTSYSCALLAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(
		_In_ HANDLE DirectoryHandle,
		_In_ HANDLE EventHandle,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID Buffer,
		_In_ ULONG BufferLength,
		_In_ ULONG CompletionFilter,
		_In_ BOOLEAN Recursive);
	//ZwNotifyChangeDirectoryFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFileEx(
		_In_     HANDLE                             FileHandle,
		_In_opt_ HANDLE                             Event,
		_In_opt_ PIO_APC_ROUTINE                    ApcRoutine,
		_In_opt_ PVOID                              ApcContext,
		_Out_    PIO_STATUS_BLOCK                   IoStatusBlock,
		_Out_    PVOID                              Buffer,
		_In_     ULONG                              Length,
		_In_     ULONG                              CompletionFilter,
		_In_     BOOLEAN                            WatchTree,
		_In_opt_ DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass);
	//ZwNotifyChangeDirectoryFileEx

	// https://learn.microsoft.com/en-us/windows/win32/api/Winternl/nf-winternl-ntopenfile
	// https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
	NTSYSCALLAPI NTSTATUS NTAPI ZwOpenFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG OpenOptions);
	// ZwOpenFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtOpenIoCompletion(
		_Out_ PHANDLE Handle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenIoCompletion

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryAttributesFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PFILE_BASIC_INFORMATION Attributes);
	//ZwQueryAttributesFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile
	NTSYSCALLAPI NTSTATUS NtQueryDirectoryFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_opt_ PUNICODE_STRING FileName,
		_In_ BOOLEAN RestartScan);
	//ZwQueryDirectoryFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfileex
	NTSYSCALLAPI NTSTATUS NtQueryDirectoryFileEx(
		_In_ HANDLE                 FileHandle,
		_In_opt_ HANDLE                 Event,
		_In_opt_ PIO_APC_ROUTINE        ApcRoutine,
		_In_opt_ PVOID                  ApcContext,
		_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
		_Out_ PVOID                  FileInformation,
		_In_ ULONG                  Length,
		FILE_INFORMATION_CLASS FileInformationClass,
		_In_ ULONG                  QueryFlags,
		_In_opt_ PUNICODE_STRING        FileName);
	//ZwQueryDirectoryFileEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryeafile
	NTSTATUS NtQueryEaFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID Buffer,
		_In_ ULONG Length,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_opt_ PVOID EaList,
		_In_ ULONG EaListLength,
		_In_opt_ PULONG EaIndex,
		_In_ BOOLEAN RestartScan);
	//ZwQueryEaFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryFullAttributesFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PFILE_NETWORK_OPEN_INFORMATION Attributes);
	//ZwQueryFullAttributesFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationByName(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass);
	//ZwQueryInformationByName

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
	NTSYSCALLAPI NTSTATUS NtQueryInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass);
	//ZwQueryInformationFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryIoCompletion(
		_In_ HANDLE IoHandle,
		_In_ ULONG Class,
		_Out_ PVOID IoInformation,
		_In_ ULONG Length,
		_Out_opt_ PULONG ReturnLength);
	//ZwQueryIoCompletion

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryquotainformationfile
	NTSYSCALLAPI NTSTATUS NtQueryQuotaInformationFile(
		_In_           HANDLE           FileHandle,
		_Out_          PIO_STATUS_BLOCK IoStatusBlock,
		_Out_          PVOID            Buffer,
		_In_           ULONG            Length,
		_In_           BOOLEAN          ReturnSingleEntry,
		_In_opt_ PVOID            SidList,
		_In_           ULONG            SidListLength,
		_In_opt_ PSID             StartSid,
		_In_           BOOLEAN          RestartScan);
	//ZwQueryQuotaInformationFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile
	NTSYSCALLAPI NTSTATUS NtQueryVolumeInformationFile(
		_In_  HANDLE               FileHandle,
		_Out_ PIO_STATUS_BLOCK     IoStatusBlock,
		_Out_ PVOID                FsInformation,
		_In_  ULONG                Length,
		_In_  FS_INFORMATION_CLASS FsInformationClass);
	//ZwQueryVolumeInformationFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile
	NTSYSCALLAPI NTSTATUS NtReadFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID Buffer,
		_In_ ULONG Length,
		_In_opt_ PLARGE_INTEGER ByteOffset,
		_In_opt_ PULONG Key);
	//ZwReadFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtReadFileScatter(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PVOID Buffer,
		_In_ ULONG BufferLength,
		_In_ PLARGE_INTEGER Offset,
		_In_opt_ PULONG Key);
	//ZwReadFileScatter

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtRemoveIoCompletion(
		_In_ HANDLE IoHandle,
		_Out_ PULONG Key,
		_Out_ PVOID Overlapped,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PLARGE_INTEGER Timeout);
	//ZwRemoveIoCompletion

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtRemoveIoCompletionEx(
		_In_ HANDLE IoCompletionHandle,
		_Out_ PVOID IoCompletionInformation,
		_In_ ULONG Count,
		_Out_ PULONG NumEntriesRemoved,
		_In_opt_ PLARGE_INTEGER Timeout,
		_In_ BOOLEAN Alertable);
	//ZwRemoveIoCompletionEx

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwseteafile
	NTSYSCALLAPI NTSTATUS NtSetEaFile(
		_In_  HANDLE           FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_  PVOID            Buffer,
		_In_  ULONG            Length
	);
	//ZwSetEaFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
	NTSYSCALLAPI NTSTATUS NtSetInformationFile(
		_In_  HANDLE                 FileHandle,
		_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
		_In_  PVOID                  FileInformation,
		_In_  ULONG                  Length,
		_In_  FILE_INFORMATION_CLASS FileInformationClass);
	//ZwSetInformationFile

	// https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtSetIoCompletion(
		_In_ HANDLE IoHandle,
		_In_ ULONG Key,
		_Inout_ PVOID Overlapped,
		_In_ NTSTATUS Status,
		_In_ ULONG DataLength);
	//ZwSetIoCompletion

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtSetIoCompletionEx(
		_In_ HANDLE IoCompletionHandle,
		_In_ HANDLE IoCompletionReserveHandle,
		_In_ PVOID KeyContext,
		_In_opt_ PVOID ApcContext,
		_In_ NTSTATUS IoStatus,
		_In_ ULONG IoStatusInformation);
	//ZwSetIoCompletionEx

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetquotainformationfile
	NTSYSCALLAPI NTSTATUS NtSetQuotaInformationFile(
		_In_  HANDLE           FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_  PVOID            Buffer,
		_In_  ULONG            Length);
	//ZwSetQuotaInformationFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetvolumeinformationfile
	NTSYSAPI NTSTATUS NtSetVolumeInformationFile(
		_In_  HANDLE               FileHandle,
		_Out_ PIO_STATUS_BLOCK     IoStatusBlock,
		_In_  PVOID                FsInformation,
		_In_  ULONG                Length,
		_In_  FS_INFORMATION_CLASS FsInformationClass);
	//ZwSetVolumeInformationFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtTranslateFilePath(
		_In_ PVOID InputPath,
		_In_ ULONG OutputType,
		_Out_ PVOID OutputFilePath,
		_In_ ULONG OutputFilePathLength);
	//ZwTranslateFilePath

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntunlockfile
	NTSYSCALLAPI NTSTATUS NtUnlockFile(
		_In_  HANDLE           FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_  PLARGE_INTEGER   ByteOffset,
		_In_  PLARGE_INTEGER   Length,
		_In_  ULONG            Key);
	//ZwUnlockFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile
	NTSYSCALLAPI NTSTATUS NtWriteFile(
		_In_           HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_          PIO_STATUS_BLOCK IoStatusBlock,
		_In_           PVOID            Buffer,
		_In_           ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key);
	//ZwWriteFile

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWriteFileGather(
		_In_ HANDLE               FileHandle,
		_In_opt_ HANDLE               Event,
		_In_opt_ PIO_APC_ROUTINE      ApcRoutine,
		_In_opt_ PVOID                ApcContext,
		_Out_ PIO_STATUS_BLOCK    IoStatusBlock,
		_In_ FILE_SEGMENT_ELEMENT SegmentArray,
		_In_ ULONG                Length,
		_In_ PLARGE_INTEGER       ByteOffset,
		_In_opt_ PULONG               Key);
	//ZwWriteFileGather

	//https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlAppxIsFileOwnedByTrustedInstaller(
		_In_ HANDLE FileHandle,
		_Out_ PBOOLEAN IsFileOwnedByTrustedInstaller);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateBootStatusDataFile(VOID);

	NTSYSAPI RTL_PATH_TYPE NTAPI RtlDetermineDosPathNameType_U(
		_In_ PCWSTR Path);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlDoesFileExists_U(
		_In_ PCWSTR FileName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosApplyFileIsolationRedirection_Ustr(
		_In_ ULONG                  Flags,
		_In_ PUNICODE_STRING        OriginalName,
		_In_ PUNICODE_STRING        Extension,
		_In_opt_ PUNICODE_STRING    StaticString,
		_In_opt_ PUNICODE_STRING    DynamicString,
		_In_opt_ PUNICODE_STRING* NewName,
		_In_ PULONG                 NewFlags,
		_In_ PSIZE_T                FileNameSize,
		_In_ PSIZE_T                RequiredLength);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlDoesNameContainWildCards(
		_In_ PUNICODE_STRING Expression);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosLongPathNameToNtPathName_U_WithStatus(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosLongPathNameToRelativeNtPathName_U_WithStatus(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosPathNameToNtPathName_U_WithStatus(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToRelativeNtPathName_U(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosPathNameToRelativeNtPathName_U_WithStatus(
		_In_ PCWSTR DosFileName,
		_Out_ PUNICODE_STRING NtFileName,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U RelativeName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlDosSearchPath_U(
		_In_ PCWSTR Path,
		_In_ PCWSTR FileName,
		_In_opt_ PCWSTR Extension,
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PWSTR Buffer,
		_Out_opt_ PWSTR* FilePart);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlDosSearchPath_Ustr(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING Path,
		_In_ PUNICODE_STRING FileName,
		_In_opt_ PUNICODE_STRING DefaultExtension,
		_Out_opt_ PUNICODE_STRING StaticString,
		_Out_opt_ PUNICODE_STRING DynamicString,
		_Out_opt_ PCUNICODE_STRING* FullFileNameOut,
		_Out_opt_ SIZE_T* FilePartPrefixCch,
		_Out_opt_ SIZE_T* BytesRequired);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetFileMUIPath(
		_In_ ULONG Flags,
		_In_ PCWSTR FilePath,
		_Inout_opt_ PCWSTR Language,
		_Inout_ PULONG LanguageLength,
		_Out_opt_ PWSTR FileMUIPath,
		_Inout_ PULONG FileMUIPathLength,
		_Inout_ PULONGLONG Enumerator);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlGetFullPathName_U(
		_In_ PCWSTR FileName,
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PWSTR Buffer,
		_Out_opt_ PWSTR* FilePart);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UEx(
		_In_ PCWSTR FileName,
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PWSTR Buffer,
		_Out_opt_ PWSTR* FilePart,
		_Out_opt_ PULONG BytesRequired);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UstrEx(
		_In_ PUNICODE_STRING FileName,
		_Inout_ PUNICODE_STRING StaticString,
		_Out_opt_ PUNICODE_STRING DynamicString,
		_Out_opt_ PUNICODE_STRING* StringUsed,
		_Out_opt_ SIZE_T* FilePartPrefixCch,
		_Out_opt_ PBOOLEAN NameInvalid,
		_Out_ RTL_PATH_TYPE* InputPathType,
		_Out_opt_ SIZE_T* BytesRequired);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetLocaleFileMappingAddress(
		_Out_ PVOID* BaseAddress,
		_Out_ PLCID DefaultLocaleId,
		_Out_ PLARGE_INTEGER DefaultCasingTableSize,
		_Out_opt_ PULONG CurrentNLSVersion);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetLengthWithoutLastFullDosOrNtPathElement(
		_Reserved_ ULONG Flags,
		_In_ PUNICODE_STRING PathString,
		_Out_ PULONG Length);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlGetLengthWithoutTrailingPathSeperators(
		_Reserved_ ULONG Flags,
		_In_ PUNICODE_STRING PathString,
		_Out_ PULONG Length);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlGetLongestNtPathLength(VOID);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtliscloudfilesplaceholder
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlIsCloudFilesPlaceholder(
		_In_ ULONG FileAttributes,
		_In_ ULONG ReparseTag);

	//https://learn.microsoft.com/fr-fr/windows/win32/devnotes/rtlisnameinexpression
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlIsNameInExpression(
		_In_ PUNICODE_STRING Expression,
		_In_ PUNICODE_STRING Name,
		_In_ BOOLEAN IgnoreCase,
		_In_opt_ PWCH UpcaseTable);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlIsNameInUnUpcasedExpression(
		_In_ PUNICODE_STRING Expression,
		_In_ PUNICODE_STRING Name,
		_In_ BOOLEAN IgnoreCase,
		_In_opt_ PWCH UpcaseTable);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlisnamelegaldos8dot3
	// See winternl.h
	NTSYSAPI BOOLEAN NTAPI RtlIsNameLegalDOS8Dot3(
		_In_ PCUNICODE_STRING Name,
		_Inout_ POEM_STRING      OemName,
		_Out_opt_ PBOOLEAN         NameContainsSpaces
	);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholderfilehandle
	NTSYSAPI NTSTATUS NTAPI RtlIsPartialPlaceholderFileHandle(
		_In_ HANDLE FileHandle,
		_Out_ PBOOLEAN IsPartialPlaceholder);

	//https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholderfileinfo
	NTSYSAPI NTSTATUS NTAPI RtlIsPartialPlaceholderFileInfo(
		_In_ PVOID InfoBuffer,
		_In_ FILE_INFORMATION_CLASS InfoClass,
		_Out_ PBOOLEAN IsPartialPlaceholder);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntrtl.h
	NTSYSAPI PVOID NTAPI RtlPcToFileHeader(
		_In_ PVOID PcValue,
		_Out_ PVOID* BaseOfImage);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseRelativeName(
		_In_ PRTL_RELATIVE_NAME_U RelativeName);

#ifdef __cplusplus
}
#endif

#endif // _NTFILE_
