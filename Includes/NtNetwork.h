#pragma once

#ifndef _NTNETWORK_
#define _NTNETWORK_
#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

	// UNRESOLVED FUNCTIONS

	//RtlIpv4AddressToStringA
	//RtlIpv4AddressToStringExA
	//RtlIpv4AddressToStringExW
	//RtlIpv4AddressToStringW
	//RtlIpv4StringToAddressA
	//RtlIpv4StringToAddressExA
	//RtlIpv4StringToAddressExW
	//RtlIpv4StringToAddressW
	//RtlIpv6AddressToStringA
	//RtlIpv6AddressToStringExA
	//RtlIpv6AddressToStringExW
	//RtlIpv6AddressToStringW
	//RtlIpv6StringToAddressA
	//RtlIpv6StringToAddressExA
	//RtlIpv6StringToAddressExW
	//RtlIpv6StringToAddressW
	// END OF UNRESOLVED FUNCTIONS

	typedef union _DL_EI48 {
		UINT8 Byte[3];
	} DL_EI48, *PDL_EI48;

	typedef union _DL_OUI {
		UINT8 Byte[3];
		struct {                    // 1st byte.  0bxxxxxxLG.
			UINT8 Group : 1;        // least significant bit.
			UINT8 Local : 1;
		} DUMMYSTRUCTNAME;
	} DL_OUI, *PDL_OUI;

	typedef union _DL_EUI48 {
		UINT8 Byte[6];
		struct {
			DL_OUI Oui;
			DL_EI48 Ei48;
		} DUMMYSTRUCTNAME;
	} DL_EUI48, *PDL_EUI48;

	// ============================ functions ============================

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa
	NTSYSAPI PSTR NTAPI RtlEthernetAddressToStringA(
		_In_  const DL_EUI48* Addr,
		_Out_ PSTR S);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringw
	NTSYSAPI PWSTR NTAPI RtlEthernetAddressToStringW(
		_In_  const DL_EUI48* Addr,
		_Out_ PWSTR S);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa
	NTSYSAPI NTSTATUS NTAPI RtlEthernetStringToAddressA(
		_In_  PCSTR    S,
		_Out_ PCSTR* Terminator,
		_Out_ DL_EUI48* Addr);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressw
	NTSYSAPI NTSTATUS NTAPI RtlEthernetStringToAddressW(
		_In_  PCWSTR   S,
		_Out_ LPCWSTR* Terminator,
		_Out_ DL_EUI48* Addr);

#ifdef __cplusplus
}
#endif

#endif // _NTNETWORK_