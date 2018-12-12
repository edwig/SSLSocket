#pragma once

#ifndef WINVER				
#define WINVER _WIN32_WINNT_VISTA  // Allow use of features specific to Windows 6 (Vista) or later
#endif

#define NO_WARN_MBCS_MFC_DEPRECATION
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define VC_EXTRALEAN

#include <afxwin.h>
#include <afxmt.h>
#include <iostream>
#include <comdef.h>
#include <memory>
