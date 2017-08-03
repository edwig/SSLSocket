/////////////////////////////////////////////////////////////////////////////
// 
// SecureServerSocket
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once
#include <functional>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include "SocketStream.h"
#include "PlainSocket.h"

class Listener;

class SecureServerSocket : public PlainSocket
{
public:
	SecureServerSocket(SOCKET p_socket,HANDLE p_stopEvent);
 ~SecureServerSocket(void);

  // Set up state for this connection
  HRESULT InitializeSSL(const void* p_buffer = nullptr,const int p_length = 0) override;

  // SocketStream interface
  int     RecvMsg    (LPVOID  p_buffer,const ULONG p_length) override;
  int     SendMsg    (LPCVOID p_buffer,const ULONG p_length) override;
	int     RecvPartial(LPVOID  p_buffer,const ULONG p_length) override;
	int     SendPartial(LPCVOID p_buffer,const ULONG p_length) override;
	int     Disconnect(int p_how = SD_BOTH) override;
  bool    Close(void) override;

	static PSecurityFunctionTable SSPI(void);

  std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> m_selectServerCert;
  std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> m_clientCertAcceptable;

private:
  static HRESULT  InitializeClass(void);
         HRESULT  LogSSLInitError(HRESULT hr);
         bool     SSPINegotiateLoop(void);
  SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext);

  static PSecurityFunctionTable g_pSSPI;
	static CredHandle g_ServerCreds;
  static CString    g_ServerName;

  // Private data
	static const int  m_maxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int  m_maxExtraSize = 50;  // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR              m_writeBuffer[m_maxMsgSize + m_maxExtraSize];       // Enough for a whole encrypted message
	CHAR              m_readBuffer[(m_maxMsgSize + m_maxExtraSize) * 2];  // Enough for two whole messages so we don't need to move data around in buffers
	DWORD             m_readBufferBytes { 0       };
	void*             m_readPointer     { nullptr };
	CtxtHandle        m_context;
	SecPkgContext_StreamSizes m_sizes;
};

