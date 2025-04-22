#pragma once

#ifndef _NTCONTEXT_
#define _NTCONTEXT_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct __declspec(align(16)) /* DECLSPEC_NOINITALL */ _CONTEXT CONTEXT, * PCONTEXT;
    typedef struct _ACTIVATION_CONTEXT ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;
    typedef struct _ACTIVATION_CONTEXT_DATA ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;
    typedef struct _ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
        ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER, * PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER;
    typedef struct _ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
        ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER, * PACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER;
    typedef struct _ACTIVATION_CONTEXT_STACK ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;
    typedef struct _ASSEMBLY_STORAGE_MAP ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;
    typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;
    typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME RTL_ACTIVATION_CONTEXT_STACK_FRAME,
        * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L467C1-L475C1
    typedef VOID(NTAPI* PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
        _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
        _In_ PACTIVATION_CONTEXT ActivationContext,
        _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
        _In_opt_ PVOID NotificationContext,
        _In_opt_ PVOID NotificationData,
        _Inout_ PBOOLEAN DisableThisNotification);

    typedef struct __declspec(align(16)) _M128A {
        ULONGLONG Low;
        LONGLONG High;
    } M128A, * PM128A;

    typedef struct __declspec(align(16)) _XSAVE_FORMAT {
        WORD ControlWord;
        WORD StatusWord;
        BYTE TagWord;
        BYTE Reserved1;
        WORD ErrorOpcode;
        DWORD ErrorOffset;
        WORD ErrorSelector;
        WORD Reserved2;
        DWORD DataOffset;
        WORD DataSelector;
        WORD Reserved3;
        DWORD MxCsr;
        DWORD MxCsr_Mask;
        M128A FloatRegisters[8];
        M128A XmmRegisters[16];
        BYTE  Reserved4[96];
    } XSAVE_FORMAT, * PXSAVE_FORMAT;
    typedef struct _XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

	// Describes the context of a thread. Copied from the SDK.
    struct __declspec(align(16)) _CONTEXT {
        // Register parameter home addresses.
        // N.B. These fields are for convience - they could be used to extend the
        //      context record in the future.
        DWORD64 P1Home;
        DWORD64 P2Home;
        DWORD64 P3Home;
        DWORD64 P4Home;
        DWORD64 P5Home;
        DWORD64 P6Home;

        // Control flags.
        DWORD ContextFlags;
        DWORD MxCsr;

        // Segment Registers and processor flags.
        WORD SegCs;
        WORD SegDs;
        WORD SegEs;
        WORD SegFs;
        WORD SegGs;
        WORD SegSs;
        DWORD EFlags;

        // Debug registers
        DWORD64 Dr0;
        DWORD64 Dr1;
        DWORD64 Dr2;
        DWORD64 Dr3;
        DWORD64 Dr6;
        DWORD64 Dr7;

        // Integer registers.
        DWORD64 Rax;
        DWORD64 Rcx;
        DWORD64 Rdx;
        DWORD64 Rbx;
        DWORD64 Rsp;
        DWORD64 Rbp;
        DWORD64 Rsi;
        DWORD64 Rdi;
        DWORD64 R8;
        DWORD64 R9;
        DWORD64 R10;
        DWORD64 R11;
        DWORD64 R12;
        DWORD64 R13;
        DWORD64 R14;
        DWORD64 R15;

        // Program counter.
        DWORD64 Rip;

        // Floating point state.
        union {
            XMM_SAVE_AREA32 FltSave;
            struct {
                M128A Header[2];
                M128A Legacy[8];
                M128A Xmm0;
                M128A Xmm1;
                M128A Xmm2;
                M128A Xmm3;
                M128A Xmm4;
                M128A Xmm5;
                M128A Xmm6;
                M128A Xmm7;
                M128A Xmm8;
                M128A Xmm9;
                M128A Xmm10;
                M128A Xmm11;
                M128A Xmm12;
                M128A Xmm13;
                M128A Xmm14;
                M128A Xmm15;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        // Vector registers.
        M128A VectorRegister[26];
        DWORD64 VectorControl;
        // Special debug control registers.
        DWORD64 DebugControl;
        DWORD64 LastBranchToRip;
        DWORD64 LastBranchFromRip;
        DWORD64 LastExceptionToRip;
        DWORD64 LastExceptionFromRip;
    };

    // https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/include/winternl.h#L227C1-L232C76
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
        PRTL_ACTIVATION_CONTEXT_STACK_FRAME Previous;
        PACTIVATION_CONTEXT ActivationContext;
        ULONG Flags;
    };

    // https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/include/winternl.h#L234C1-L241C56
    struct _ACTIVATION_CONTEXT_STACK {
        RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
        LIST_ENTRY FrameListCache;
        ULONG Flags;
        ULONG NextCookieSequenceNumber;
        ULONG_PTR StackId;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L13C1-L14C1
#define ACTIVATION_CONTEXT_FLAG_NO_INHERIT 0x00000001

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L48C1-L50C1
#define ACTIVATION_CONTEXT_DATA_TOC_HEADER_DENSE 0x00000001
#define ACTIVATION_CONTEXT_DATA_TOC_HEADER_INORDER 0x00000002

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L67C1-L74C1
    struct _ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER {
        ULONG HeaderSize;
        ULONG EntryCount;
        ULONG FirstEntryOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY[], from ACTIVATION_CONTEXT_DATA base
        ULONG Flags;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L85
    struct _ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER {
        ULONG HeaderSize;
        ULONG HashAlgorithm; // HASH_STRING_ALGORITHM_*
        ULONG EntryCount;
        ULONG FirstEntryOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY[], from ACTIVATION_CONTEXT_DATA base
        ULONG AssemblyInformationSectionOffset; // to resolve section-relative offsets
    };

    // https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/ntsxs.h#L36C1-L46C54
    struct _ACTIVATION_CONTEXT_DATA {
        ULONG Magic;
        ULONG HeaderSize;
        ULONG FormatVersion;
        ULONG TotalSize;
        ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
        ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
        ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
        ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
    };

    // https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/ntsxs.h#L445
    struct _ASSEMBLY_STORAGE_MAP_ENTRY {
        ULONG Flags;
        UNICODE_STRING DosPath;
        HANDLE Handle;
    };

    // https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/ntsxs.h#L454C1-L459C48
    struct _ASSEMBLY_STORAGE_MAP {
        ULONG Flags;
        ULONG AssemblyCount;
        PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntsxs.h#L476
    struct _ACTIVATION_CONTEXT {
        LONG RefCount;
        ULONG FLAGS;
        PACTIVATION_CONTEXT_DATA ActivationContextData;
        PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
        PVOID NotificationContext;
        ULONG SentNotifications[8];
        ULONG DisabledNotifications[8];
        ASSEMBLY_STORAGE_MAP StorageMap;
        PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
    };

#ifdef __cplusplus
}
#endif

#endif // _NTCONTEXT_