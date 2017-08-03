/////////////////////////////////////////////////////////////////////////////
// 
// Transport (binding SecureServerSocket to a listener)
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "Transport.h"
#include "SecureServerSocket.h"
#include "Listener.h"
#include "Logging.h"
#include "PlainSocket.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

Transport::Transport(SOCKET p_socket,Listener* p_listener) // constructor requires a socket already assigned
 	         :m_listener(p_listener)
	         ,m_serverSocket(nullptr)
{
	m_serverSocket = new SecureServerSocket(p_socket,m_stopEvent);
  m_serverSocket->SetSendTimeoutSeconds(60);
  m_serverSocket->SetRecvTimeoutSeconds(60);
  m_serverSocket->Initialize();
}

// And the destructor
Transport::~Transport()
{
	delete m_serverSocket;
  m_serverSocket = nullptr;
}

