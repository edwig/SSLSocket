#pragma once

#ifndef WINVER				
#define WINVER _WIN32_WINNT_VISTA  // Allow use of features specific to Windows 6 (Vista) or later
#endif

#define NO_WARN_MBCS_MFC_DEPRECATION
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// Define a bool to check if this is a DEBUG or RELEASE build

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif

#include <afxwin.h>
#include <afxmt.h>
#include <iostream>

// #define Stringize( L )			#L
// #define MakeString( M, L )		M(L)
// #define $Line					\
// 	MakeString(Stringize, __LINE__)
// #define Reminder				\
// 	__FILE__ "(" $Line ") : Reminder: "
// usage #pragma message(Reminder "your message here")
