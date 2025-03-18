#pragma once

#ifndef _NTNETWORK_
#define _NTNETWORK_
#include "NtCommonDefs.h"

extern "C" {

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

}

#endif // _NTNETWORK_