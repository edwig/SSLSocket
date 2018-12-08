/////////////////////////////////////////////////////////////////////////////
// 
// Listener
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "Listener.h"
#include <process.h>
#include <strsafe.h>
#include <atlconv.h>
#include <WS2tcpip.h>
#include "SecureServerSocket.h"
#include "Transport.h"
#include "SSLUtilities.h"
#include "Logging.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CListerner object, listens for connections on one thread, and initiates a worker
// thread each time a client connects.
Listener::Listener()
	       :m_stopEvent(FALSE, TRUE)
         ,m_workerThreadCount(0)
         ,m_listenerThread(NULL)
         ,m_numListenSockets(0)
{
	for (int i = 0; i<FD_SETSIZE; i++)
	{
		m_listenSockets[i] = INVALID_SOCKET;
		m_hSocketEvents[i] = nullptr;
	}
}

Listener::~Listener(void)
{
	EndListening();
	for (int i = 0; i<FD_SETSIZE; i++)
	{
    if(m_listenSockets[i] != INVALID_SOCKET)
    {
      closesocket(m_listenSockets[i]);
    }
    if(m_hSocketEvents[i])
    {
      CloseHandle(m_hSocketEvents[i]);
    }
	}
  WSACleanup();
}

// This is the individual worker process, all it does is start, change its name to something useful,
// then call the Lambda function passed in via the BeginListening method
UINT __cdecl Listener::Worker(void* p_argument)
{
	Transport*          transport = reinterpret_cast<Transport*>(p_argument);
	Listener*           listener  = transport->m_listener;
  SecureServerSocket* socket    = transport->m_serverSocket;

  // Connect the certificate functions to the server socket
  socket->m_selectServerCert     = listener->m_selectServerCert;
  socket->m_clientCertAcceptable = listener->m_clientCertAcceptable;

	SetThreadName("Connection Worker");

  // Doing our work
  listener->m_workerThreadCount++;
 (listener->m_actualwork)((SocketStream*)transport->m_serverSocket);
  listener->m_workerThreadCount--;

  delete transport;
  return 0;
}

// Worker process for connection listening
UINT __cdecl Listener::ListenerWorker(LPVOID v)
{
  // See _beginthread call for parameter definition
	Listener* listener = reinterpret_cast<Listener *>(v); 

	SetThreadName("Listener");
	listener->Listen();
	return 0;
}

// Initialize the listener, set up the socket to listen on, or return an error
Listener::ErrorType 
Listener::Initialize(int p_tcpListenPort)
{
	TCHAR MsgText[100];
	CString portText;
	portText.Format(_T("%i"),p_tcpListenPort);

	WSADATA wsadata;
  if(WSAStartup(MAKEWORD(2,0),&wsadata))
  {
    return UnknownError;
  }
	// Get list of addresses to listen on
	ADDRINFOT Hints, *AddrInfo, *AI;
	memset(&Hints, 0, sizeof (Hints));
	Hints.ai_family   = PF_UNSPEC;    // Meaning IP4 or IP6
	Hints.ai_socktype = SOCK_STREAM;  // Streaming sockets only
	Hints.ai_flags    = AI_NUMERICHOST | AI_PASSIVE;
	if (GetAddrInfo(nullptr, portText, &Hints, &AddrInfo) != 0)
	{
		StringCchPrintf(MsgText, _countof(MsgText), _T("getaddressinfo error: %i"), GetLastError());
		LogError(MsgText);
		return UnknownError;
	}

	// Create one or more passive sockets to listen on
	int i;
	for (i = 0, AI = AddrInfo; AI != nullptr; AI = AI->ai_next)
	{
		// Did we receive more addresses than we can handle?  Highly unlikely, but check anyway.
		if (i == FD_SETSIZE) break;

		// Only support PF_INET and PF_INET6.  If something else, skip to next address.
		if ((AI->ai_family != AF_INET) && (AI->ai_family != AF_INET6)) continue;

		m_hSocketEvents[i] = CreateEvent(nullptr,   // no security attributes
			                               true,		  // manual reset event
			                               false,		  // not signaled
			                               nullptr);	// no name

    // Check that we got the event
    if(!(m_hSocketEvents[i]))
    {
      return UnknownError;
    }

    // Create listen socket
		m_listenSockets[i] = WSASocket(AI->ai_family, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if(m_listenSockets[i] == INVALID_SOCKET)
    {
      return SocketUnusable;
    }

    // Bind listen socket to this address
		int rc = bind(m_listenSockets[i], AI->ai_addr, (int)AI->ai_addrlen);
		if(rc)
		{
      if(WSAGetLastError() == WSAEADDRINUSE)
      {
        return SocketInuse;
      }
      else
      {
        return SocketUnusable;
      }
		}

    // Listen async on this socket
    if(listen(m_listenSockets[i],10))
    {
      return SocketUnusable;
    }
    // Accept the FD_ACCEPT-ing event of the socket
    if(WSAEventSelect(m_listenSockets[i],m_hSocketEvents[i],FD_ACCEPT))
    {
      return SocketUnusable;
    }
		i++;
	}
  // Register number of simultaneous sockets.
	m_numListenSockets = i;

	return NoError;
}

// Start listening for connections, if a timeout is specified keep listening until then
void Listener::BeginListening(std::function<void(SocketStream * StreamSock)> actualwork)
{
	m_actualwork = actualwork;
	m_listenerThread = AfxBeginThread(ListenerWorker, this);
}

// Stop listening, tells the listener thread it can stop, then waits for it to terminate
void Listener::EndListening(void)
{
	m_stopEvent.SetEvent();
	if (m_listenerThread)
	{
		WaitForSingleObject(m_listenerThread->m_hThread, INFINITE); // Will auto delete
	}
	m_listenerThread = nullptr;
}

// Listen for connections until the "stop" event is caused, this is invoked on
// its own thread
void Listener::Listen(void)
{
	HANDLE events[FD_SETSIZE+1];
	SOCKET readSocket = NULL;
	DWORD  wait       = 0;

  m_workerThreadCount = 0;

	DebugMsg("Start Listener::Listen method");

	events[0] = m_stopEvent;

 	// Add the events for each socket type (two at most, one for IPv4, one for IPv6)
	for (int i=0; i<m_numListenSockets; i++)
	{
		events[i+1] = m_hSocketEvents[i];
	}

	// Loop until there is a problem or the shutdown event is caused
	while (true)
	{
		wait = WaitForMultipleObjects(m_numListenSockets+1, events, false, INFINITE);

		if (wait == WAIT_OBJECT_0)
		{
			DebugMsg("Listener::Listen received a stop event");
			break;
		}
		int iMyIndex = wait-1;

		WSAResetEvent(m_hSocketEvents[iMyIndex]);
		readSocket = accept(m_listenSockets[iMyIndex], 0, 0);
		if (readSocket == INVALID_SOCKET)
		{
			LogError("readSocket == INVALID_SOCKET");
			break;
		}

		// A request to open a socket has been received, begin a thread to handle that connection
		DebugMsg("Starting worker");
		
		Transport* transport = new Transport(readSocket, this); // Deleted by worker thread
    if(transport->GetIsConnected())
    {
      AfxBeginThread(Worker,transport);
    }
    else
    {
      delete transport;
    }
		readSocket = INVALID_SOCKET;
  }
	// There has been a problem, wait for all the worker threads to terminate
	Sleep(100);
	m_workerThreadLock.Lock();
	while (m_workerThreadCount)
	{
		m_workerThreadLock.Unlock();
		Sleep(100);
		DebugMsg("Waiting for all workers to terminate: worker thread count = %i", m_workerThreadCount);
		m_workerThreadLock.Lock();
	};

  if((readSocket != NULL) && (readSocket != INVALID_SOCKET))
  {
    closesocket(readSocket);
  }
	DebugMsg("End Listen method");
}
