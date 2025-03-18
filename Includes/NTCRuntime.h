#pragma once

#ifndef _NTCRUNTIME_
#define _NTCRUNTIME_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

	// NO UNDEFINED FUNCTIONS

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/--c-specific-handler2
	_CRTIMP __C_specific_handler(
		_In_    struct _EXCEPTION_RECORD* ExceptionRecord,
		_In_    void* EstablisherFrame,
		_Inout_ struct _CONTEXT* ContextRecord,
		_Inout_ struct _DISPATCHER_CONTEXT* DispatcherContext);

	// This function can't be declared because it expect two arguments, one from the stack
	// and the other to be transmited in the RAX register.
	// https://learn.microsoft.com/en-us/windows/win32/devnotes/-win32-__chkstk
	// NTSYSAPI unsigned __int64 __cdecl _chkstk();
	
	//https://learn.microsoft.com/fr-fr/cpp/c-runtime-library/reference/isascii-isascii-iswascii?view=msvc-170
	NTSYSAPI int NTAPI __isascii(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/iscsym-functions?view=msvc-170
	NTSYSAPI int NTAPI __iscsym(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/iscsym-functions?view=msvc-170
	NTSYSAPI int NTAPI __iscsymf(
		int c);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI __misaligned_access(VOID);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/toascii-toascii?view=msvc-170
	NTSYSAPI int NTAPI __toascii(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atoi64-atoi64-l-wtoi64-wtoi64-l?view=msvc-170
	NTSYSAPI __int64 NTAPI _atoi64(
		const char* str);

	NTSYSAPI int* NTAPI _errno();

	// Reversed. This seems to be an obscure shadow variable used by the compiler whenever some
	// float related stuff and the linker want to make sure we are not messing with C-runtime /
	// other default libraries confusion.
	NTSYSAPI unsigned int _fltused;

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI char* NTAPI _i64toa(
		long long value,
		char* buffer,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _i64toa_s(
		long long value,
		char* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _i64tow(
		long long value,
		wchar_t* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPPI _i64tow_s(
		long long value,
		wchar_t* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI char* NTAPI_itoa(
		int value,
		char* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _itoa_s(
		int value,
		char* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _itow(
		int value,
		wchar_t* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _itow_s(
		int value,
		wchar_t* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/lfind?view=msvc-170
	NTSYSAPI void* NTAPI _lfind(
		const void* key,
		const void* base,
		unsigned int* num,
		unsigned int width,
		int(__cdecl* compare)(const void*, const void*));

	// Reversed. A wrapper around RtlUnwind.
	NTSYSAPI VOID NTAPI _local_unwind(
		_In_opt_ PVOID TargetFrame,
		_In_opt_ PVOID TargetIp);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI char* NTAPI _ltoa(
		long value,
		char* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ltoa_s(
		long value,
		char* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _ltow(
		long value,
		wchar_t* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ltow_s(
		long value,
		wchar_t* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/makepath-s-wmakepath-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _makepath_s(
		char* path,
		size_t sizeInBytes,
		const char* drive,
		const char* dir,
		const char* fname,
		const char* ext);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memccpy?view=msvc-170
	NTSYSAPI void* NTAPI _memccpy(
		void* dest,
		const void* src,
		int c,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memicmp-memicmp-l?view=msvc-170
	NTSYSAPI int NTAPI _memicmp(
		const void* buffer1,
		const void* buffer2,
		size_t count);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/setjmp?view=msvc-170
	// https://learn.microsoft.com/en-us/cpp/cpp/using-setjmp-longjmp?view=msvc-170
#ifndef _JMP_BUF_DEFINED
#define _JMP_BUF_DEFINED
	typedef struct _VCRT_ALIGN(16) _SETJMP_FLOAT128
	{
		unsigned __int64 Part[2];
	} SETJMP_FLOAT128;
#define _JBLEN  16
	typedef SETJMP_FLOAT128 _JBTYPE;
	typedef _JBTYPE jmp_buf[_JBLEN];
#endif
	NTSYSAPI int __cdecl setjmp(
		jmp_buf env);

	// Unclear.
	NTSYSAPI int __cdecl setjmpex(
		jmp_buf env);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-snprintf-snprintf-l-snwprintf-snwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _snprintf(
		char* buffer,
		size_t count,
		const char* format[,
		argument] ...);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-s-snprintf-s-l-snwprintf-s-snwprintf-s-l?view=msvc-170
	NTSYSAPI int NTAPI _snprintf_s(
		char* buffer,
		size_t sizeOfBuffer,
		size_t count,
		const char* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snscanf-s-snscanf-s-l-snwscanf-s-snwscanf-s-l?view=msvc-170
	NTSYSAPI int __cdecl _snscanf_s(
		const char* input,
		size_t length,
		const char* format[,
		argument_list]);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-snprintf-snprintf-l-snwprintf-snwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _snwprintf(
		wchar_t* buffer,
		size_t count,
		const wchar_t* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-s-snprintf-s-l-snwprintf-s-snwprintf-s-l?view=msvc-170
	NTSYSAPI int __cdecl _snwprintf_s(
		wchar_t* buffer,
		size_t sizeOfBuffer,
		size_t count,
		const wchar_t* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snscanf-s-snscanf-s-l-snwscanf-s-snwscanf-s-l?view=msvc-170
	NTSYSAPI int __cdecl _snwscanf_s(
		const wchar_t* input,
		size_t length,
		const wchar_t* format[,
		argument_list]);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/splitpath-wsplitpath?view=msvc-170
	NTSYSAPI void NTAPI _splitpath(
		const char* path,
		char* drive,
		char* dir,
		char* fname,
		char* ext);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/splitpath-s-wsplitpath-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _splitpath_s(
		const char* path,
		char* drive,
		size_t driveNumberOfElements,
		char* dir,
		size_t dirNumberOfElements,
		char* fname,
		size_t nameNumberOfElements,
		char* ext,
		size_t extNumberOfElements);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l?view=msvc-170
#define _strcmpi _stricmp /* Alias */
	NTSYSAPI int NTAPI _stricmp(
		const char* string1,
		const char* string2);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlwr-wcslwr-mbslwr-strlwr-l-wcslwr-l-mbslwr-l?view=msvc-170
	NTSYSAPI char* NTAPI _strlwr(
		char* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlwr-s-strlwr-s-l-mbslwr-s-mbslwr-s-l-wcslwr-s-wcslwr-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _strlwr_s(
		char* str,
		size_t numberOfElements);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l?view=msvc-170
	NTSYSAPI int NTAPI _strnicmp(
		const char* string1,
		const char* string2,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnset-s-strnset-s-l-wcsnset-s-wcsnset-s-l-mbsnset-s-mbsnset-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _strnset_s(
		char* str,
		size_t numberOfElements,
		int c,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strset-s-strset-s-l-wcsset-s-wcsset-s-l-mbsset-s-mbsset-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _strset_s(
		char* str,
		size_t numberOfElements,
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-170
	NTSYSAPI char* NTAPI _strupr(
		char* str);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-s-strupr-s-l-mbsupr-s-mbsupr-s-l-wcsupr-s-wcsupr-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _strupr_s(
		char* str,
		size_t numberOfElements);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _swprintf(
		wchar_t* buffer,
		const wchar_t* format[,
		argument]...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI char* NTAPI _ui64toa(
		unsigned long long value,
		char* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ui64toa_s(
		unsigned long long value,
		char* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _ui64tow(
		unsigned long long value,
		wchar_t* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ui64tow_s(
		unsigned long long value,
		wchar_t* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI char* NTAPI ultoa(
		unsigned long value,
		char* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ultoa_s(
		unsigned long value,
		char* buffer,
		size_t size,
		int radix);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-itow?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _ultow(
		unsigned long value,
		wchar_t* buffer,
		int radix);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/itoa-s-itow-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _ui64tow_s(
		unsigned long long value,
		wchar_t* buffer,
		size_t size,
		int radix);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vscprintf-vscprintf-l-vscwprintf-vscwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _vscprintf(
		const char* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vscprintf-vscprintf-l-vscwprintf-vscwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _vscwprintf(
		const wchar_t* format,
		va_list argptr);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-vsnprintf-vsnprintf-l-vsnwprintf-vsnwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _vsnprintf(
		char* buffer,
		size_t count,
		const char* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-s-vsnprintf-s-vsnprintf-s-l-vsnwprintf-s-vsnwprintf-s-l?view=msvc-170
	NTSYSAPI int NTAPI _vsnprintf_s(
		char* buffer,
		size_t sizeOfBuffer,
		size_t count,
		const char* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-vsnprintf-vsnprintf-l-vsnwprintf-vsnwprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _vsnwprintf(
		wchar_t* buffer,
		size_t count,
		const wchar_t* format,
		va_list argptr);
	
	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-s-vsnprintf-s-vsnprintf-s-l-vsnwprintf-s-vsnwprintf-s-l?view=msvc-170
	NTSYSAPI int NTAPI _vsnwprintf_s(
		wchar_t* buffer,
		size_t sizeOfBuffer,
		size_t count,
		const wchar_t* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsprintf-vsprintf-l-vswprintf-vswprintf-l-vswprintf-l?view=msvc-170
	NTSYSAPI int NTAPI _vswprintf(
		wchar_t* buffer,
		size_t count,
		const wchar_t* format,
		va_list argptr);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l?view=msvc-170
	NTSYSAPI int NTAPI _wcsicmp(
		const wchar_t* string1,
		const wchar_t* string2);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlwr-wcslwr-mbslwr-strlwr-l-wcslwr-l-mbslwr-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _wcslwr(
		wchar_t* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlwr-s-strlwr-s-l-mbslwr-s-mbslwr-s-l-wcslwr-s-wcslwr-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _wcslwr_s(
		wchar_t* str,
		size_t numberOfElements);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l?view=msvc-170
	NTSYSAPI int NTAPI _wcsnicmp(
		const wchar_t* string1,
		const wchar_t* string2,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnset-s-strnset-s-l-wcsnset-s-wcsnset-s-l-mbsnset-s-mbsnset-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _wcsnset_s(
		wchar_t* str,
		size_t numberOfElements,
		wchar_t c,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strset-s-strset-s-l-wcsset-s-wcsset-s-l-mbsset-s-mbsset-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _wcsset_s(
		wchar_t* str,
		size_t numberOfElements,
		wchar_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoi64-wcstoi64-strtoi64-l-wcstoi64-l?view=msvc-170
	NTSYSAPI __int64 NTAPI _wcstoi64(
		const wchar_t* strSource,
		wchar_t** endptr,
		int base);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoui64-wcstoui64-strtoui64-l-wcstoui64-l?view=msvc-170
	NTSYSAPI unsigned __int64 NTAPI _wcstoui64(
		const wchar_t* strSource,
		wchar_t** endptr,
		int base);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr?view=msvc-170
	NTSYSAPI wchar_t* NTAPI _wcsupr(
		wchar_t* str);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-s-strupr-s-l-mbsupr-s-mbsupr-s-l-wcsupr-s-wcsupr-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI _wcsupr_s(
		wchar_t* str,
		size_t numberOfElements);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/makepath-s-wmakepath-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _wmakepath_s(
		wchar_t* path,
		size_t sizeInWords,
		const wchar_t* drive,
		const wchar_t* dir,
		const wchar_t* fname,
		const wchar_t* ext);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/splitpath-s-wsplitpath-s?view=msvc-170
	NTSYSAPI errno_t NTAPI _wsplitpath_s(
		const wchar_t* path,
		wchar_t* drive,
		size_t driveNumberOfElements,
		wchar_t* dir,
		size_t dirNumberOfElements,
		wchar_t* fname,
		size_t nameNumberOfElements,
		wchar_t* ext,
		size_t extNumberOfElements);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atoi-atoi-l-wtoi-wtoi-l?view=msvc-170
	NTSYSAPI int NTAPI _wtoi(
		const wchar_t* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atoi64-atoi64-l-wtoi64-wtoi64-l?view=msvc-170
	NTSYSAPI __int64 NTAPI _wtoi64(
		const wchar_t* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atol-atol-l-wtol-wtol-l?view=msvc-170
	NTSYSAPI long NTAPI _wtol(
		const wchar_t* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/abs-labs-llabs-abs64?view=msvc-170
	NTSYSAPI int NTAPI abs(
		int n);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atan-atanf-atanl-atan2-atan2f-atan2l?view=msvc-170
	NTSYSAPI float NTAPI atan(
		float x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atan-atanf-atanl-atan2-atan2f-atan2l?view=msvc-170
	NTSYSAPI double NTAPI atan2(
		double y,
		double x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atoi-atoi-l-wtoi-wtoi-l?view=msvc-170
	NTSYSAPI int NTAPI atoi(
		const char* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atol-atol-l-wtol-wtol-l?view=msvc-170
	NTSYSAPI long NTAPI atol(
		const char* str);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/bsearch?view=msvc-170
	NTSYSAPI void* NTAPI bsearch(
		const void* key,
		const void* base,
		size_t num,
		size_t width,
		int(__cdecl* compare) (const void* key, const void* datum));

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/bsearch-s?view=msvc-170
	NTSYSAPI void* NTAPI bsearch_s(
		const void* key,
		const void* base,
		size_t number,
		size_t width,
		int(__cdecl* compare) (void*, const void* key, const void* datum),
		void* context);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ceil-ceilf-ceill?view=msvc-170
	NTSYSAPI double NTAPI ceil(
		double x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/cos-cosf-cosl?view=msvc-170
	NTSYSAPI double NTAPI cos(
		double x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fabs-fabsf-fabsl?view=msvc-170
	NTSYSAPI double NTAPI fabs(
		double x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/floor-floorf-floorl?view=msvc-170
	NTSYSAPI double NTAPI floor(
		double x);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isalnum-iswalnum-isalnum-l-iswalnum-l?view=msvc-170
	int __cdecl isalnum(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isalpha-iswalpha-isalpha-l-iswalpha-l?view=msvc-170
	NTSYSAPI int NTAPI isalpha(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/iscntrl-iswcntrl-iscntrl-l-iswcntrl-l?view=msvc-170
	NTSYSAPI int iscntrl(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isdigit-iswdigit-isdigit-l-iswdigit-l?view=msvc-170
	NTSYSAPI int NTAPI isdigit(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isgraph-iswgraph-isgraph-l-iswgraph-l?view=msvc-170
	NTSYSAPI int NTAPI isgraph(
		int c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/islower-iswlower-islower-l-iswlower-l?view=msvc-170
	NTSYSAPI int NTAPI islower(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isprint-iswprint-isprint-l-iswprint-l?view=msvc-170
	NTSYSAPI int NTAPI isprint(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ispunct-iswpunct-ispunct-l-iswpunct-l?view=msvc-170
	NTSYSAPI int NTAPI ispunct(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isspace-iswspace-isspace-l-iswspace-l?view=msvc-170
	NTSYSAPI int NTAPI isspace(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isupper-isupper-l-iswupper-iswupper-l?view=msvc-170
	NTSYSAPI int NTAPI isupper(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isalnum-iswalnum-isalnum-l-iswalnum-l?view=msvc-170
	NTSYSAPI int NTAPI iswalnum(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isalpha-iswalpha-isalpha-l-iswalpha-l?view=msvc-170
	NTSYSAPI int NTAPI iswalpha(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isascii-isascii-iswascii?view=msvc-170
	NTSYSAPI int NTAPI iswascii(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isctype-iswctype-isctype-l-iswctype-l?view=msvc-170
	NTSYSAPI int NTAPI iswctype(
		wint_t c,
		wctype_t desc);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isdigit-iswdigit-isdigit-l-iswdigit-l?view=msvc-170
	NTSYSAPI int NTAPI iswdigit(
		wint_t c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isgraph-iswgraph-isgraph-l-iswgraph-l?view=msvc-170
	NTSYSAPI int NTAPI iswgraph(
		wint_t c);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/islower-iswlower-islower-l-iswlower-l?view=msvc-170
	NTSYSAPI int NTAPI iswlower(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isprint-iswprint-isprint-l-iswprint-l?view=msvc-170
	NTSYSAPI int NTAPI iswprint(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isspace-iswspace-isspace-l-iswspace-l?view=msvc-170
	NTSYSAPI int NTAPI iswspace(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isxdigit-iswxdigit-isxdigit-l-iswxdigit-l?view=msvc-170
	NTSYSAPI int NTAPI iswxdigit(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isxdigit-iswxdigit-isxdigit-l-iswxdigit-l?view=msvc-170
	NTSYSAPI int NTAPI isxdigit(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/abs-labs-llabs-abs64?view=msvc-170
	NTSYSAPI long NTAPI labs(
		long n);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/log-logf-log10-log10f?view=msvc-170
	NTSYSAPI double NTAPI log(
		double x);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/longjmp?view=msvc-170
	NTSYSAPI void NTAPI longjmp(
		jmp_buf env,
		int value);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/mbstowcs-mbstowcs-l?view=msvc-170
	NTSYSAPI size_t NTAPI mbstowcs(
		wchar_t* wcstr,
		const char* mbstr,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memchr-wmemchr?view=msvc-170
	NTSYSAPI void* NTAPI memchr(
#ifdef __cplusplus
		void* buffer,
#else
		const void* buffer,
#endif
		int c,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memcmp-wmemcmp?view=msvc-170
	NTSYSAPI int NTAPI memcmp(
		const void* buffer1,
		const void* buffer2,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=msvc-170
	NTSYSAPI void* NTAPI memcpy(
		void* dest,
		const void* src,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-s-wmemcpy-s?view=msvc-170
	NTSYSAPI errno_t NTAPI memcpy_s(
		void* dest,
		size_t destSize,
		const void* src,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memmove-wmemmove?view=msvc-170
	NTSYSAPI void* NTAPI memmove(
		void* dest,
		const void* src,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memmove-s-wmemmove-s?view=msvc-170
	NTSYSAPI errno_t NTAPI memmove_s(
		void* dest,
		size_t numberOfElements,
		const void* src,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memset-wmemset?view=msvc-170
	NTSYSAPI void* NTAPI memset(
		void* dest,
		int c,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/pow-powf-powl?view=msvc-170
	NTSYSAPI double NTAPI pow(
		double x,
		double y);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/qsort?view=msvc-170
	NTSYSAPI void NTAPI qsort(
		void* base,
		size_t number,
		size_t width,
		int(__cdecl* compare)(const void*, const void*));

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/qsort-s?view=msvc-170
	NTSYSAPI void NTAPI qsort_s(
		void* base,
		size_t num,
		size_t width,
		int(__cdecl* compare)(void*, const void*, const void*),
		void* context);

#ifdef __cplusplus
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sin-sinf-sinl?view=msvc-170
	NTSYSAPI float NTAPI sin(
		float x);
#endif

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-170
	NTSYSAPI int __cdecl sprintf(
		char* buffer,
		const char* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-s-sprintf-s-l-swprintf-s-swprintf-s-l?view=msvc-170
	NTSYSAPI int __cdecl sprintf_s(
		char* buffer,
		size_t sizeOfBuffer,
		const char* format,
		...);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sqrt-sqrtf-sqrtl?view=msvc-170
	NTSYSAPI double NTAPI sqrt(
		double x);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sscanf-sscanf-l-swscanf-swscanf-l?view=msvc-170
	NTSYSAPI int __cdecl sscanf(
		const char* buffer,
		const char* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sscanf-s-sscanf-s-l-swscanf-s-swscanf-s-l?view=msvc-170
	NTSYSAPI int __cdecl sscanf_s(
		const char* buffer,
		const char* format[,
		argument] ...);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcat-wcscat-mbscat?view=msvc-170
	NTSYSAPI char* NTAPI strcat(
		char* strDestination,
		const char* strSource);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcat-s-wcscat-s-mbscat-s?view=msvc-170
	NTSYSAPI errno_t NTAPI strcat_s(
		char* strDestination,
		size_t numberOfElements,
		const char* strSource);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strchr-wcschr-mbschr-mbschr-l?view=msvc-170
	NTSYSAPI char* NTAPI strchr(
#ifdef __cplusplus
		char* str,
#else
		const char* str,
#endif
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-170
	NTSYSAPI int NTAPI strcmp(
		const char* string1,
		const char* string2);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-wcscpy-mbscpy?view=msvc-170
	NTSYSAPI char* NTAPI strcpy(
		char* strDestination,
		const char* strSource);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-s-wcscpy-s-mbscpy-s?view=msvc-170
	NTSYSAPI errno_t NTAPI strcpy_s(
		char* dest,
		rsize_t dest_size,
		const char* src);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcspn-wcscspn-mbscspn-mbscspn-l?view=msvc-170
	NTSYSAPI size_t NTAPI strcspn(
		const char* str,
		const char* strCharSet);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlen-wcslen-mbslen-mbslen-l-mbstrlen-mbstrlen-l?view=msvc-170
	NTSYSAPI size_t NTAPI strlen(
		const char* str);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncat-strncat-l-wcsncat-wcsncat-l-mbsncat-mbsncat-l?view=msvc-170
	NTSYSAPI char* NTAPI strncat(
		char* strDest,
		const char* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncat-s-strncat-s-l-wcsncat-s-wcsncat-s-l-mbsncat-s-mbsncat-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI strncat_s(
		char* strDest,
		size_t numberOfElements,
		const char* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l?view=msvc-170
	NTSYSAPI int NTAPI strncmp(
		const char* string1,
		const char* string2,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-strncpy-l-wcsncpy-wcsncpy-l-mbsncpy-mbsncpy-l?view=msvc-170
	NTSYSAPI char* NTAPI strncpy(
		char* strDest,
		const char* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-s-strncpy-s-l-wcsncpy-s-wcsncpy-s-l-mbsncpy-s-mbsncpy-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI strncpy_s(
		char* strDest,
		size_t numberOfElements,
		const char* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s?view=msvc-170
	NTSYSAPI size_t NTAPI strnlen(
		const char* str,
		size_t numberOfElements);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strpbrk-wcspbrk-mbspbrk-mbspbrk-l?view=msvc-170
	NTSYSAPI char* NTAPI strpbrk(
#ifdef __cplusplus
		char* str,
#else
		const char* str,
#endif
		const char* strCharSet
	);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l?view=msvc-170
	NTSYSAPI char* NTAPI strrchr(
#ifdef __cplusplus
		char* str,
#else
		const char* str,
#endif
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strspn-wcsspn-mbsspn-mbsspn-l?view=msvc-170
	NTSYSAPI size_t NTAPI strspn(
		const char* str,
		const char* strCharSet);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l?view=msvc-170
	NTSYSAPI char* NTAPI strstr(
#ifdef __cplusplus
		char* str,
#else
		const char* str,
#endif
		const char* strSearch
	);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-s-strtok-s-l-wcstok-s-wcstok-s-l-mbstok-s-mbstok-s-l?view=msvc-170
	NTSYSAPI char* NTAPI strtok_s(
		char* str,
		const char* delimiters,
		char** context);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtol-wcstol-strtol-l-wcstol-l?view=msvc-170
	NTSYSAPI long NTAPI strtol(
		const char* string,
		char** end_ptr,
		int base);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoul-strtoul-l-wcstoul-wcstoul-l?view=msvc-170
	NTSYSAPI unsigned long NTAPI strtoul(
		const char* strSource,
		char** endptr,
		int base);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-170
	NTSYSAPI int __cdecl swprintf(
		wchar_t* buffer,
		size_t count,
		const wchar_t* format[,
		argument]...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-s-sprintf-s-l-swprintf-s-swprintf-s-l?view=msvc-170
	NTSYSAPI int __cdecl swprintf_s(
		wchar_t* buffer,
		size_t sizeOfBuffer,
		const wchar_t* format,
		...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sscanf-s-sscanf-s-l-swscanf-s-swscanf-s-l?view=msvc-170
	NTSYSAPI int __cdecl swscanf_s(
		const wchar_t* buffer,
		const wchar_t* format[,
		argument] ...);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tan-tanf-tanl?view=msvc-170
	NTSYSAPI double NTAPI tan(
		double x);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tolower-tolower-towlower-tolower-l-towlower-l?view=msvc-170
	NTSYSAPI int NTAPI tolower(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/toupper-toupper-towupper-toupper-l-towupper-l?view=msvc-170
	NTSYSAPI int NTAPI toupper(
		int c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tolower-tolower-towlower-tolower-l-towlower-l?view=msvc-170
	NTSYSAPI int NTAPI towlower(
		wint_t c);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/toupper-toupper-towupper-toupper-l-towupper-l?view=msvc-170
	NTSYSAPI int NTAPI towupper(
		wint_t c);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-vdbgprintex
	NTSYSAPI ULONG NTAPI vDbgPrintEx(
		_In_ ULONG   ComponentId,
		_In_ ULONG   Level,
		_In_ PCCH    Format,
		_In_ va_list arglist);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-vdbgprintexwithprefix
	NTSYSAPI ULONG vDbgPrintExWithPrefix(
		_In_ PCCH    Prefix,
		_In_ ULONG   ComponentId,
		_In_ ULONG   Level,
		_In_ PCCH    Format,
		_In_ va_list arglist);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsprintf-vsprintf-l-vswprintf-vswprintf-l-vswprintf-l?view=msvc-170
	NTSYSAPI int NTAPI vsprintf(
		char* buffer,
		const char* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsprintf-s-vsprintf-s-l-vswprintf-s-vswprintf-s-l?view=msvc-170
	NTSYSAPI int NTAPI vsprintf_s(
		char* buffer,
		size_t numberOfElements,
		const char* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsprintf-vsprintf-l-vswprintf-vswprintf-l-vswprintf-l?view=msvc-170
	NTSYSAPI int NTAPI vswprintf_s(
		wchar_t* buffer,
		size_t numberOfElements,
		const wchar_t* format,
		va_list argptr);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcat-wcscat-mbscat?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcscat(
		wchar_t* strDestination,
		const wchar_t* strSource);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcat-s-wcscat-s-mbscat-s?view=msvc-170
	NTSYSAPI errno_t NTAPI wcscat_s(
		wchar_t* strDestination,
		size_t numberOfElements,
		const wchar_t* strSource);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strchr-wcschr-mbschr-mbschr-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcschr(
#ifdef __cplusplus
		wchar_t* str,
#else
		const wchar_t* str,
#endif
		wchar_t c
	);
	
	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-170
	NTSYSAPI int NTAPI wcscmp(
		const wchar_t* string1,
		const wchar_t* string2
	);
	
	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-wcscpy-mbscpy?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcscpy(
		wchar_t* strDestination,
		const wchar_t* strSource
	);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-s-wcscpy-s-mbscpy-s?view=msvc-170
	NTSYSAPI errno_t NTAPI wcscpy_s(
		wchar_t* dest,
		rsize_t dest_size,
		const wchar_t* src);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcspn-wcscspn-mbscspn-mbscspn-l?view=msvc-170
	NTSYSAPI size_t NTAPI wcscspn(
		const wchar_t* str,
		const wchar_t* strCharSet);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strlen-wcslen-mbslen-mbslen-l-mbstrlen-mbstrlen-l?view=msvc-170
	NTSYSAPI size_t NTAPI wcslen(
		const wchar_t* str);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncat-strncat-l-wcsncat-wcsncat-l-mbsncat-mbsncat-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcsncat(
		wchar_t* strDest,
		const wchar_t* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncat-s-strncat-s-l-wcsncat-s-wcsncat-s-l-mbsncat-s-mbsncat-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI wcsncat_s(
		wchar_t* strDest,
		size_t numberOfElements,
		const wchar_t* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l?view=msvc-170
	NTSYSAPI int NTAPI wcsncmp(
		const wchar_t* string1,
		const wchar_t* string2,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-strncpy-l-wcsncpy-wcsncpy-l-mbsncpy-mbsncpy-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcsncpy(
		wchar_t* strDest,
		const wchar_t* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-s-strncpy-s-l-wcsncpy-s-wcsncpy-s-l-mbsncpy-s-mbsncpy-s-l?view=msvc-170
	NTSYSAPI errno_t NTAPI wcsncpy_s(
		wchar_t* strDest,
		size_t numberOfElements,
		const wchar_t* strSource,
		size_t count);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s?view=msvc-170
	NTSYSAPI size_t NTAPI wcsnlen(
		const wchar_t* str,
		size_t numberOfElements);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strpbrk-wcspbrk-mbspbrk-mbspbrk-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcspbrk(
#ifdef __cplusplus
		wchar_t* str,
#else
		const wchar_t* str,
#endif
		const wchar_t* strCharSet);
	
	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcsrchr(
#ifdef __cplusplus
		wchar_t* str,
#else
		const wchar_t* str,
#endif
		wchar_t c);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strspn-wcsspn-mbsspn-mbsspn-l?view=msvc-170
	NTSYSAPI size_t NTAPI wcsspn(
		const wchar_t* str,
		const wchar_t* strCharSet);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcsstr(
#ifdef __cplusplus
		wchar_t* str,
#else
		const wchar_t* str,
#endif
		const wchar_t* strSearch
	);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-s-strtok-s-l-wcstok-s-wcstok-s-l-mbstok-s-mbstok-s-l?view=msvc-170
	NTSYSAPI wchar_t* NTAPI wcstok_s(
		wchar_t* str,
		const wchar_t* delimiters,
		wchar_t** context);

	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtol-wcstol-strtol-l-wcstol-l?view=msvc-170
	NTSYSAPI long NTAPI wcstol(
		const wchar_t* string,
		wchar_t** end_ptr,
		int base);
	
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/wcstombs-wcstombs-l?view=msvc-170
	NTSYSAPI size_t NTAPI wcstombs(
		char* mbstr,
		const wchar_t* wcstr,
		size_t count);

	//https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoul-strtoul-l-wcstoul-wcstoul-l?view=msvc-170
	NTSYSAPI unsigned long NTAPI wcstoul(
		const wchar_t* strSource,
		wchar_t** endptr,
		int base);

#ifdef __cplusplus
}
#endif

#endif // NTCRUNTIME
