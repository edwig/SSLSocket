/////////////////////////////////////////////////////////////////////////////
// 
// SecureClientSocket
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <functional>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include "SecurityHandle.h"
#include "PlainSocket.h"

// Possible SSL/TLS levels we can use
typedef enum _SSL_Class
{
  SSL_2  = SP_PROT_SSL2_CLIENT
 ,SSL_3  = SP_PROT_SSL3_CLIENT
 ,TLS_10 = SP_PROT_TLS1_CLIENT
 ,TLS_11 = SP_PROT_TLS1_1_CLIENT
 ,TLS_12 = SP_PROT_TLS1_2_CLIENT
}
SSLProtClass;

class SecureClientSocket : public PlainSocket
{
public:
	SecureClientSocket(HANDLE p_stopEvent);
  virtual ~SecureClientSocket(void);

  // Set up for a SSL protection level
  void    SetSSLProtectionLevel(SSLProtClass p_class);
  // Set up state for this connection
  HRESULT InitializeSSL(const void* p_buffer = nullptr,const int p_length = 0);

  // SocketStream interface
  int     RecvMsg    (LPVOID  p_buffer,const ULONG p_length) override;
  int     SendMsg    (LPCVOID p_buffer,const ULONG p_length) override;
	int     RecvPartial(LPVOID  p_buffer,const ULONG p_length) override;
	int     SendPartial(LPCVOID p_buffer,const ULONG p_length) override;
  bool    Close() override;
  int     Disconnect(int p_side = SD_BOTH) override;

  static  PSecurityFunctionTable SSPI(void);
  bool    GetServerCertNameMatches();
  bool    GetServerCertTrusted();

  // Attributes
  static PSecurityFunctionTable g_pSSPI;
  std::function<bool(PCCERT_CONTEXT pCertContext,const bool trusted,const bool matchingName)> m_serverCertAcceptable;
  std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext,SecPkgContext_IssuerListInfoEx * pIssuerListInfo,bool Required)> m_selectClientCertificate;

private:
  static HRESULT         InitializeSecurityInterface(void);
         SECURITY_STATUS SSPINegotiateLoop(TCHAR* ServerName);
         SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds,const PCCERT_CONTEXT pCertContext);
         SECURITY_STATUS GetNewClientCredentials();

  // CONSTANTS
  static const int  MaxMsgSize   = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
  static const int  MaxExtraSize = 50;    // Also arbitrary, current header is 5 bytes, trailer 36

  // Private data for SSL/TLS connections
  CredentialHandle  m_clientCredentials;
	CHAR              m_writeBuffer[MaxMsgSize + MaxExtraSize];       // Enough for a whole encrypted message
	CHAR              m_readBuffer[(MaxMsgSize + MaxExtraSize) * 2];  // Enough for two whole messages so we don't need to move data around in buffers
  CHAR              m_plainText  [MaxMsgSize * 2];                  // Extra plaintext data not yet delivered
	DWORD             m_readBufferBytes { 0       };
	CHAR*             m_plainTextPtr    { nullptr };
  DWORD             m_plainTextBytes  { 0       };
	void*             m_readPointer     { nullptr };
  SecurityContextHandle     m_context;
	SecPkgContext_StreamSizes m_sizes;
	bool              m_serverCertNameMatches { false  };
	bool              m_serverCertTrusted     { false  };
  SSLProtClass      m_sslClass              { TLS_12 };
};

