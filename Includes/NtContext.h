#pragma once

#ifndef _NTCONTEXT_
#define _NTCONTEXT_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct __declspec(align(16)) /* DECLSPEC_NOINITALL */ _CONTEXT CONTEXT, * PCONTEXT;
    typedef struct _ACTIVATION_CONTEXT_STACK ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;
    typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME RTL_ACTIVATION_CONTEXT_STACK_FRAME,
        * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

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
    typedef struct _ACTIVATION_CONTEXT ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;
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

#ifdef __cplusplus
}
#endif

#endif // _NTCONTEXT_