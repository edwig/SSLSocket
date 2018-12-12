/////////////////////////////////////////////////////////////////////////////
// 
// SSL Helper functions
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <cryptuiapi.h>
#include "Logging.h"

// Automatically link to these libraries
#pragma comment(lib,"secur32.lib")
#pragma comment(lib,"cryptui.lib")

#ifndef SCH_USE_STRONG_CRYPTO   // Needs KB 2868725 which is only in Windows 7+
#define SCH_USE_STRONG_CRYPTO   0x00400000
#endif

// handy functions declared in this file
HRESULT         ShowCertInfo          (PCCERT_CONTEXT  pCertContext, CString Title);
HRESULT         CertTrusted           (PCCERT_CONTEXT  pCertContext);
bool            MatchCertHostName     (PCCERT_CONTEXT  pCertContext, LPCSTR hostname);
SECURITY_STATUS CertFindClient        (PCCERT_CONTEXT& pCertContext, const LPCTSTR pszSubjectName = NULL);
SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT& pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo);
CString         GetHostName(COMPUTER_NAME_FORMAT WhichName = ComputerNameDnsHostname);
CString         GetUserName(void);
bool            IsUserAdmin();
void            SetThreadName(char* threadName);
void            SetThreadName(char* threadName,DWORD dwThreadID);

// Server side
SECURITY_STATUS CertFindServerByName(PCCERT_CONTEXT & pCertContext,LPCTSTR pszSubjectName,boolean fUserStore);
