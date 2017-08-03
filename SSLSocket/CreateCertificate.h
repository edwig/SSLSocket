//////////////////////////////////////////////////////////////////////////
//
// CreateCertificate (client or server)
//
// based on a sample found at:
// http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
// Create a self-signed certificate and store it in the machine personal store
// 
#pragma once
#include "wincrypt.h"
#pragma comment(lib, "crypt32.lib")

// defined in another source file (CreateCertificate.cpp)
PCCERT_CONTEXT CreateCertificate(bool   p_machineCert  = false
                                ,LPCSTR p_subject      = nullptr
                                ,LPCSTR p_friendlyName = nullptr
                                ,LPCSTR p_description  = nullptr);

