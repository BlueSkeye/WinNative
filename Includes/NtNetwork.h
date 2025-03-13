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
		[in]  const DL_EUI48* Addr,
		[out] PSTR S);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringw
	NTSYSAPI PWSTR NTAPI RtlEthernetAddressToStringW(
		[in]  const DL_EUI48* Addr,
		[out] PWSTR S);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa
	NTSYSAPI NTSTATUS NTAPI RtlEthernetStringToAddressA(
		[in]  PCSTR    S,
		[out] PCSTR* Terminator,
		[out] DL_EUI48* Addr);

	// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressw
	NTSYSAPI NTSTATUS NTAPI RtlEthernetStringToAddressW(
		[in]  PCWSTR   S,
		[out] LPCWSTR* Terminator,
		[out] DL_EUI48* Addr);

}

#endif // _NTNETWORK_