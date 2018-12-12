//////////////////////////////////////////////////////////////////////////
//
// Abstracted Interface for a socket-stream
// - Abstracted for client/server side
// - Abstracted for plain/secure sockets
//
// This is the hierarchy of objects derived from SocketStream:
// 1 SocketStream
//   2 PlainSocket
//     3 SecureClientSocket
//     3 SecureServerSocket
//
//////////////////////////////////////////////////////////////////////////
#pragma once
#include <winsock2.h>

class SocketStream
{
public:
  // Set up SSL/TLS state for this connection
  virtual HRESULT InitializeSSL(const void* p_buffer = nullptr,const int p_length = 0) = 0;

  // Receives exactly p_length bytes of data and returns the amount sent     - or SOCKET_ERROR if it times out
  virtual int     RecvMsg    (LPVOID  p_buffer,const ULONG p_length) = 0;
  // Sends exactly    p_length bytes of data and returns the amount sent     - or SOCKET_ERROR if it times out
  virtual int     SendMsg    (LPCVOID p_buffer,const ULONG p_length) = 0;
  // Receives up to   p_length bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	virtual int     RecvPartial(LPVOID  p_buffer,const ULONG p_length) = 0;
  // Sends    up to   p_length bytes of data and returns the amount sent     - or SOCKET_ERROR if it times out
	virtual int     SendPartial(LPCVOID p_buffer,const ULONG p_length) = 0;

  // Last error state of deepest derived class
	virtual DWORD   GetLastError() = 0;
  // Disconnect the socket SD_RECEIVE / SD_SEND / SD_BOTH
  virtual int     Disconnect(int p_side = SD_BOTH) = 0;
  // Returns true if the close worked
	virtual bool    Close() = 0; 

  // Are we running in secure SSL/TLS mode?
  bool            InSecureMode() { return m_secureMode; };

protected:
  // Are we initialized in secure mode or not?
  bool m_secureMode { false };
};

