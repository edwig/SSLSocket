/////////////////////////////////////////////////////////////////////////////
// 
// Transport (binding SecureServerSocket to a listener)
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once

#include <comdef.h>
#include "PlainSocket.h"
#include "SocketStream.h"
#include "EventWrapper.h"

class CPrtMsg;
class Listener;
class SecureServerSocket;

class Transport  
{
public:
  Transport(SOCKET p_socket,Listener* p_listener);
  virtual ~Transport();

  Listener*            m_listener;
  SecureServerSocket*  m_serverSocket;

  bool GetIsConnected();

private:
  EventWrapper         m_stopEvent;
};

inline bool
Transport::GetIsConnected()
{
  return (m_serverSocket != nullptr);
}