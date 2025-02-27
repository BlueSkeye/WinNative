#pragma once

#ifndef _NTFILE_
#define _NTFILE_

#include "NtCommonDefs.h"

extern "C" {

//LdrGetFileNameFromLoadAsDataTable

//LdrOpenImageFileOptionsKey
//LdrQueryImageFileExecutionOptions
//LdrQueryImageFileExecutionOptionsEx
//LdrQueryImageFileKeyOption

	// https://processhacker.sourceforge.io/doc/ntmmapi_8h.html
	NTSYSCALLAPI NTSTATUS NTAPI NtAreMappedFilesTheSame(
		_In_ PVOID File1MappedAsAnImage,
		_In_ PVOID File2MappedAsFile);
	//ZwAreMappedFilesTheSame

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
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
	NTSYSCALLAPI BOOL WINAPI NtCancelIoFile(
		_In_ HANDLE hFile
	);
	//ZwCancelIoFile

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/nt-cancel-io-file-ex
	NTSYSCALLAPI BOOL WINAPI NtCancelIoFileEx(
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
	// See winternl.h
	// NtCreateFile
	// ZwCreateFile

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
	NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(
		_Out_ PHANDLE IoHandle,
		_In_ FILE_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG NumberOfConcurrentThreads);
	//ZwCreateIoCompletion

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtCreateMailslotFile(
		OUT PHANDLE             MailslotFileHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		OUT PIO_STATUS_BLOCK    IoStatusBlock,
		IN ULONG                CreateOptions,
		IN ULONG                MailslotQuota,
		IN ULONG                MaxMessageSize,
		IN PLARGE_INTEGER       ReadTimeOut);
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
		_In_opt_ PLARGE_INTEGER DefaultTimeout
	);
	//ZwCreateNamedPipeFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateWaitCompletionPacket(
		_Out_ PHANDLE WaitCompletionPacketHandle,
		_In_ FILE_ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwCreateWaitCompletionPacket

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwdeletefile
	NTSYSCALLAPI NTSYSAPI NTSTATUS NtDeleteFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);
	//ZwDeleteFile

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile
	// See winternl.h
	
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

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwflushbuffersfileex
	NTSYSAPI NTSTATUS NtFlushBuffersFileEx(
		[in]  HANDLE           FileHandle,
		ULONG            FLags,
		PVOID            Parameters,
		ULONG            ParametersSize,
		[out] PIO_STATUS_BLOCK IoStatusBlock);
	//ZwFlushBuffersFileEx

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwfscontrolfile
	NTSYSAPI NTSTATUS NtFsControlFile(
		[in]            HANDLE           FileHandle,
		[in, optional]  HANDLE           Event,
		[in, optional]  PIO_APC_ROUTINE  ApcRoutine,
		[in, optional]  PVOID            ApcContext,
		[out]           PIO_STATUS_BLOCK IoStatusBlock,
		[in]            ULONG            FsControlCode,
		[in, optional]  PVOID            InputBuffer,
		[in]            ULONG            InputBufferLength,
		[out, optional] PVOID            OutputBuffer,
		[in]            ULONG            OutputBufferLength);
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
	// See winternl.h
	// NtOpenFile
	// ZwOpenFile

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtOpenIoCompletion(
		_Out_ PHANDLE Handle,
		_In_ FILE_ACCESS_MASK DesiredAccess,
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
		[in]           HANDLE           FileHandle,
		[out]          PIO_STATUS_BLOCK IoStatusBlock,
		[out]          PVOID            Buffer,
		[in]           ULONG            Length,
		[in]           BOOLEAN          ReturnSingleEntry,
		[in, optional] PVOID            EaList,
		[in]           ULONG            EaListLength,
		[in, optional] PULONG           EaIndex,
		[in]           BOOLEAN          RestartScan
	);
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
		[in]           HANDLE           FileHandle,
		[out]          PIO_STATUS_BLOCK IoStatusBlock,
		[out]          PVOID            Buffer,
		[in]           ULONG            Length,
		[in]           BOOLEAN          ReturnSingleEntry,
		[in, optional] PVOID            SidList,
		[in]           ULONG            SidListLength,
		[in, optional] PSID             StartSid,
		[in]           BOOLEAN          RestartScan);
	//ZwQueryQuotaInformationFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile
	NTSYSCALLAPI NTSTATUS NtQueryVolumeInformationFile(
		[in]  HANDLE               FileHandle,
		[out] PIO_STATUS_BLOCK     IoStatusBlock,
		[out] PVOID                FsInformation,
		[in]  ULONG                Length,
		[in]  FS_INFORMATION_CLASS FsInformationClass);
	//ZwQueryVolumeInformationFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile
	NTSYSCALLAPI NTSTATUS NtReadFile(
		[in]           HANDLE           FileHandle,
		[in, optional] HANDLE           Event,
		[in, optional] PIO_APC_ROUTINE  ApcRoutine,
		[in, optional] PVOID            ApcContext,
		[out]          PIO_STATUS_BLOCK IoStatusBlock,
		[out]          PVOID            Buffer,
		[in]           ULONG            Length,
		[in, optional] PLARGE_INTEGER   ByteOffset,
		[in, optional] PULONG           Key);
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
		[in]  HANDLE           FileHandle,
		[out] PIO_STATUS_BLOCK IoStatusBlock,
		[in]  PVOID            Buffer,
		[in]  ULONG            Length
	);
	//ZwSetEaFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
	NTSYSCALLAPI NTSTATUS NtSetInformationFile(
		[in]  HANDLE                 FileHandle,
		[out] PIO_STATUS_BLOCK       IoStatusBlock,
		[in]  PVOID                  FileInformation,
		[in]  ULONG                  Length,
		[in]  FILE_INFORMATION_CLASS FileInformationClass);
	//ZwSetInformationFile

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
		[in]  HANDLE           FileHandle,
		[out] PIO_STATUS_BLOCK IoStatusBlock,
		[in]  PVOID            Buffer,
		[in]  ULONG            Length);
	//ZwSetQuotaInformationFile

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetvolumeinformationfile
	NTSYSAPI NTSTATUS NtSetVolumeInformationFile(
		[in]  HANDLE               FileHandle,
		[out] PIO_STATUS_BLOCK     IoStatusBlock,
		[in]  PVOID                FsInformation,
		[in]  ULONG                Length,
		[in]  FS_INFORMATION_CLASS FsInformationClass);
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
		[in]  HANDLE           FileHandle,
		[out] PIO_STATUS_BLOCK IoStatusBlock,
		[in]  PLARGE_INTEGER   ByteOffset,
		[in]  PLARGE_INTEGER   Length,
		[in]  ULONG            Key);
	//ZwUnlockFile

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile
	NTSYSCALLAPI NTSTATUS NtWriteFile(
		[in]           HANDLE           FileHandle,
		[in, optional] HANDLE           Event,
		[in, optional] PIO_APC_ROUTINE  ApcRoutine,
		[in, optional] PVOID            ApcContext,
		[out]          PIO_STATUS_BLOCK IoStatusBlock,
		[in]           PVOID            Buffer,
		[in]           ULONG            Length,
		[in, optional] PLARGE_INTEGER   ByteOffset,
		[in, optional] PULONG           Key);
	//ZwWriteFile

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWriteFileGather(
		IN HANDLE               FileHandle,
		IN HANDLE               Event OPTIONAL,
		IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
		IN PVOID                ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK    IoStatusBlock,
		IN FILE_SEGMENT_ELEMENT SegmentArray,
		IN ULONG                Length,
		IN PLARGE_INTEGER       ByteOffset,
		IN PULONG               Key OPTIONAL);
	//ZwWriteFileGather

//RtlAppxIsFileOwnedByTrustedInstaller
//RtlCreateBootStatusDataFile
//RtlDoesFileExists_U
//RtlDosApplyFileIsolationRedirection_Ustr
//RtlDoesNameContainWildCards
//RtlDosLongPathNameToNtPathName_U_WithStatus
//RtlDosLongPathNameToRelativeNtPathName_U_WithStatus
//RtlDosPathNameToNtPathName_U
//RtlDosPathNameToNtPathName_U_WithStatus
//RtlDosPathNameToRelativeNtPathName_U
//RtlDosPathNameToRelativeNtPathName_U_WithStatus
//RtlDosSearchPath_U
//RtlDosSearchPath_Ustr
//RtlGetFileMUIPath
//RtlGetFullPathName_U
//RtlGetFullPathName_UEx
//RtlGetFullPathName_UstrEx
//RtlGetLocaleFileMappingAddress
//RtlGetLengthWithoutLastFullDosOrNtPathElement
//RtlGetLengthWithoutTrailingPathSeperators
//RtlGetLongestNtPathLength
//RtlIsCloudFilesPlaceholder
//RtlIsNameInExpression
//RtlIsNameInUnUpcasedExpression
	// See winternl.h
	// RtlIsNameLegalDOS8Dot3
//RtlIsPartialPlaceholderFileHandle
//RtlIsPartialPlaceholderFileInfo
//RtlPcToFileHeader

}

#endif // _NTFILE_
