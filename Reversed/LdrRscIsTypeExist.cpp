#include "..\Include\NtCommonDefs.h"

typedef struct _STR1_BUFFER {
    DWORD BufferDataOffset;
    DWORD BufferDataLength;
} STR1_BUFFER, *PSTR1_BUFFER;

typedef struct _STR1 {
    __int64 field_0;
    __int64 field_8;
    __int64 field_10;
    __int64 field_18;
    __int64 field_20;
    __int64 field_28;
    __int64 field_30;
    __int64 field_38;
    __int64 field_40;
    __int64 field_48;
    DWORD field_50;
    STR1_BUFFER Buffer;
    STR1_BUFFER ResourceBuffer;
    STR1_BUFFER field_64;
    DWORD field_6C;
    DWORD field_70;
    DWORD field_74;
    __int64 field_78;
};

#define MAX_RESOURCE_ID 0x10000

NTSYSAPI NTSTATUS NTAPI LdrRscIsTypeExist(
    PSTR1 pStr1,
    // Either a pointer to a string or a resource identifier (<= 0x100000)
    wchar_t* nameOrResourceId,
    __int64 UNUSED,
    PDWORD pFlags) // Flags
{
    if (NULL == pStr1) return STATUS_INVALID_PARAMETER;
    if (NULL == pFlags) return STATUS_INVALID_PARAMETER;

    __try {
        if (MAX_RESOURCE_ID <= nameOrResourceId) {
            // Resource identifier.
            DWORD resourcesCount = pStr1->ResourceBuffer.BufferDataLength / 4;
            PUINT pResourceBuffer = (PUINT)(pStr1->ResourceBuffer.BufferDataOffset + (char*)pStr1);
            while (0 >= --resourcesCount) {
                if (0 == ((DWORD)nameOrResourceId - *(pResourceBuffer++))) { break; }
            }
            if (0 > resourcesCount) { *pFlags |= 0x40000; }
            DWORD var_50 = pStr1->field_70;
            PUINT var_38 = (PUINT)(pStr1->field_6C + (char*)pStr1);
            var_50 = resourcesCount;
            while (0 >= --var_50) {
                if (0 == (R8D - *(var_38++)) { break; }
            }
            if (0 == var_50) { *pFlags |= 0x20000; }
            return STATUS_SUCCESS;
        }

        BYTE increment;
        DWORD var_68 = pStr1->field_58 / 2;
        wchar_t* arg_0 = (wchar_t*)(pStr1->field_54 + (char*)pStr1);
        while (true) {
            if (0 < var_68) {
                if (0 == *arg_0) {
                    *pFlags |= 0x40000;
                    break;
                }
                if (0 == _wsicmp(nameOrResourceId, arg_0)) {
                    int length = -1;
                    while (0 != arg_0[++length]) { /* NOTHING */ }
                    arg_0 = &arg_0[length + 1];
                    var_68 -= (length + 1);
                    continue;
                }
            }
            else {
                if (0 == *arg_0) {
                    increment = 0;
                    *pFlags |= 0x40000;
                }
                else if (0 == var_68) {
                    *pFlags |= 0x40000;
                }
                break;
            }
        }
        
        DWORD remainingStringCharacters = pStr1->field_68 / 2;
        wchar_t* var_48 = (wchar_t*)(pStr1->field_64 + (char*)pStr1);
        if (MAX_RESOURCE_ID >= var_48) {
            if ((0 != *var_48) && (0 < remainingStringCharacters)) {
                if (0 == R15b) { *pFlags |= 0x20000; }
            }
            else {
                *pFlags |= 0x20000;
            }
            return STATUS_SUCCESS;
        }
        while (true) {
            if (0 >= remainingStringCharacters) {
                if ((0 != *var_48) && (0 < remainingStringCharacters)) {
                    if (0 == R15b) { *pFlags |= 0x20000; }
                }
                else {
                    *pFlags |= 0x20000;
                }
                return STATUS_SUCCESS;
            }
            if (0 == *var_48) {
                *pFlags |= 0x20000;
                return STATUS_SUCCESS;
            }
            if (0 == _wcsicmp(nameOrResourceId, var_48)) {
                if ((0 == *var_48) || (0 >= remainingStringCharacters)) {
                    *pFlags |= 0x20000;
                }
                return STATUS_SUCCESS;
            }
            int length = -1;
            while (0 != var_48[++length]);
            var_48 = &var_48[length + 1];
            remainingStringCharacters -= (length + 1);
            continue;
        }
        return STATUS_SUCCESS;
    }
    catch (NTSTATUS status) {
        return status;
    }
}
