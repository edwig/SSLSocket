/////////////////////////////////////////////////////////////////////////////
// 
// SSL Tracer functions
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include <schannel.h>
#include <cryptuiapi.h>
#pragma comment(lib,"cryptui.lib")
#ifndef SCH_USE_STRONG_CRYPTO // Needs KB 2868725 which is only in Windows 7+
#define SCH_USE_STRONG_CRYPTO 0x00400000
#endif

class SSLTracer
{
public:
  SSLTracer(const byte * BufPtr, const int BufBytes);
 ~SSLTracer();

	// Max length of handshake data buffer
	void    TraceHandshake();
  // Is this packet a complete client initialize packet
  bool    IsClientInitialize();
  // Get SNI provided hostname
  CString GetSNIHostname();

private:
  bool CanDecode();

  const byte* OriginalBufPtr;
  const byte* DataPtr; // Points to data inside message
  const byte* BufEnd;
  const int   MaxBufBytes;
  UINT8       contentType,major,minor;
  UINT16      length;
  UINT8       handshakeType;
  UINT16      handshakeLength;
  bool        decoded;
};
