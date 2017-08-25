/////////////////////////////////////////////////////////////////////////////
// 
// PlainSocket
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include <process.h>
#include <stdlib.h>
#include <WS2tcpip.h>
#include <MSTcpIP.h>
#include "PlainSocket.h"
#include "Logging.h"
#include <mswsock.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Current activated version of WSA Socket driver library
WSADATA PlainSocket::m_wsaData = {0, 0};

PlainSocket::PlainSocket(HANDLE p_stopEvent)
            :m_stopEvent(p_stopEvent)
{
}

// Constructor for an already connected socket
PlainSocket::PlainSocket(SOCKET p_socket,HANDLE p_stopEvent)
            :m_actualSocket(p_socket)
            ,m_stopEvent(p_stopEvent)
{
}

// Destructor
PlainSocket::~PlainSocket()
{
  WSACloseEvent(m_read_event);
  WSACloseEvent(m_write_event);
  closesocket(m_actualSocket);
  m_read_event   = nullptr;
  m_write_event  = nullptr;
  m_actualSocket = NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CActiveSock member functions

void
PlainSocket::Initialize()
{
	// Initialize the WinSock subsystem.
	//
  if(m_wsaData.wHighVersion == 0)
  {
    if(WSAStartup(0x0101,&m_wsaData) == SOCKET_ERROR)
    {
      LogError("Error %d returned by WSAStartup",GetLastError());
      throw "WSAStartup error";
    }
  }
  // Re-Set to sane values
	m_lastError     = 0;
	m_recvInitiated = false;

  // Getting the events and check for invalid values
  if(!m_read_event)
  {
    m_read_event = WSACreateEvent();  
  }
	WSAResetEvent(m_read_event);
  if(!m_write_event)
  {
    m_write_event = WSACreateEvent(); 
  }
	WSAResetEvent(m_write_event);
	
  if(m_read_event == WSA_INVALID_EVENT || m_write_event == WSA_INVALID_EVENT)
  {
    throw "WSACreateEvent failed";
  }

  // Set socket options for TCP/IP
  int rc = true;
	setsockopt(m_actualSocket, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(int));

  m_initDone = true;
}

// Find connection type (AF_INET (IPv4) or AF_INET6 (IPv6))
int
PlainSocket::FindConnectType(LPCTSTR p_host,char* p_portname)
{
  ADDRINFO  hints;
  ADDRINFO* result;
  memset(&hints,0,sizeof(ADDRINFO));
  int type = AF_INET;

  // Request streaming type socket in TCP/IP protocol
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  DWORD retval = getaddrinfo(p_host,p_portname,&hints,&result);
  if(retval == 0)
  {
    if((result->ai_family == AF_INET6) ||
       (result->ai_family == AF_INET))
    {
      type = result->ai_family;
    }
    freeaddrinfo(result);
  }
  else
  {
    // MESS_INETTYPE 
    LogError("Cannot determine if internet is of type IP4 or IP6");
  }
  // Assume it's IP4 as a default
  return type;
}

// Connect as a client to a server actively
bool 
PlainSocket::Connect(LPCTSTR p_hostName, USHORT p_portNumber)
{
	SOCKADDR_STORAGE localAddr  = {0};
	SOCKADDR_STORAGE remoteAddr = {0};
	DWORD sizeLocalAddr  = sizeof(localAddr);
	DWORD sizeRemoteAddr = sizeof(remoteAddr);
	char  portName[10]   = {0};
  BOOL    bSuccess     = FALSE;
	timeval timeout      = {0};
  int     result       = 0;

  if(m_initDone == false)
  {
    Initialize();
  }

  // Convert port number and find IPv4 or IPv6
  _itoa_s(p_portNumber, portName, _countof(portName), 10);
  int type = FindConnectType(p_hostName,portName);

  // Create the actual physical socket
	m_actualSocket = socket(type, SOCK_STREAM, 0);
	if (m_actualSocket == INVALID_SOCKET)
  {
		LogError("Socket failed with error: %d\n", WSAGetLastError());
		return false;
	}

  // Find timeout for the connection
  timeout.tv_sec = GetConnTimeoutSeconds();
	CTime Now = CTime::GetCurrentTime();

	// Note that WSAConnectByName requires Vista or Server 2008
	bSuccess = WSAConnectByName(m_actualSocket
                             ,const_cast<LPTSTR>(p_hostName)
                             ,portName
                             ,&sizeLocalAddr
                             ,(SOCKADDR*)&localAddr
                             ,&sizeRemoteAddr
                             ,(SOCKADDR*)&remoteAddr
                             ,&timeout
                             ,nullptr);

	CTimeSpan HowLong = CTime::GetCurrentTime() - Now;
	if (!bSuccess)
  {
		m_lastError = WSAGetLastError();
		LogError("**** WSAConnectByName Error %d connecting to \"%s\" (%s)", 
				     m_lastError,
				     p_hostName, 
				     portName);
		closesocket(m_actualSocket);
		return false;       
	}

  DebugMsg("Connection made in %ld second(s)",HowLong.GetTotalSeconds());

  // Activate previously set options
	result = setsockopt(m_actualSocket, SOL_SOCKET,SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
	if (result == SOCKET_ERROR)
  {
		m_lastError = WSAGetLastError();
		LogError("setsockopt for SO_UPDATE_CONNECT_CONTEXT failed with error: %d", m_lastError);
		closesocket(m_actualSocket);
		return false;       
	}

  result = true;
	// At this point we have a connection, so set up keep-alive so we can detect if the host disconnects
	// This code is commented out because it does not seen to be helpful
  if(m_useKeepalive)
  {
    result = ActivateKeepalive();
  }

  // We are now a client side socket
  m_active = true;

  // Remember what we connected on
  m_hostName   = p_hostName;
  m_portNumber = p_portNumber;

	return result;
}

bool PlainSocket::ActivateKeepalive()
{
  BOOL so_keepalive = m_useKeepalive;
  int iResult = setsockopt(m_actualSocket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&so_keepalive, sizeof(so_keepalive));
	if (iResult == SOCKET_ERROR)
  {
		m_lastError = WSAGetLastError();
		LogError("Setsockopt for SO_KEEPALIVE failed with error: %d\n",m_lastError);
		closesocket(m_actualSocket);
    m_actualSocket = NULL;
		return false;       
	}

  // Now set keep alive timings, if activated
  if(m_useKeepalive)
  {
    DWORD dwBytes = 0;
    tcp_keepalive setting = { 0 };

    setting.onoff             = 1;
    setting.keepalivetime     = m_keepaliveTime     * CLOCKS_PER_SEC;     // Keep Alive in x milli seconds
    setting.keepaliveinterval = m_keepaliveInterval * CLOCKS_PER_SEC;     // Resend if No-Reply
    if (WSAIoctl(m_actualSocket
                ,SIO_KEEPALIVE_VALS
                ,&setting
    	          ,sizeof(setting)
                ,nullptr          // Result buffer sReturned
                ,0                // Size of result buffer
                ,&dwBytes         // Total bytes
                ,nullptr          // Pointer to OVERLAPPED
                ,nullptr) != 0)   // Completion routine
    {
      m_lastError = WSAGetLastError() ;
      LogError("WSAIoctl to set keep-alive failed with error: %d\n", m_lastError);
      closesocket(m_actualSocket);
      m_actualSocket = NULL;
      return false;       
    }
  }
  return true;
}

// Set up SSL/TLS state for this connection:
// NEVER USED ON PLAIN SOCKETS! Only on derived classes!!
HRESULT 
PlainSocket::InitializeSSL(const void* /*p_buffer*/ /*= nullptr*/,const int /*p_length*/ /*= 0*/)
{
  return SOCKET_ERROR;
}

// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int PlainSocket::RecvPartial(LPVOID p_buffer, const ULONG p_length)
{
	WSABUF    buffer;
	WSAEVENT  hEvents[2] = {m_read_event, m_stopEvent};
  DWORD			bytes_read = 0;
  DWORD     msg_flags  = 0;
	int       received   = 0;

	if (m_recvInitiated)
	{
		// Special case, the previous read timed out, so we are trying again, maybe it completed in the meantime
		received      = SOCKET_ERROR;
		m_lastError   = WSA_IO_PENDING;
		m_recvEndTime = 0;
	}
	else
	{
		// Normal case, the last read completed normally, now we're reading again

		// Setup the buffers array
		buffer.buf = static_cast<char*>(p_buffer);
		buffer.len = p_length;
	
		// Create the overlapped I/O event and structures
		memset(&m_os, 0, sizeof(OVERLAPPED));
		m_os.hEvent = hEvents[1];
		WSAResetEvent(m_os.hEvent);
		m_recvInitiated = true;
		received = WSARecv(m_actualSocket, &buffer, 1, &bytes_read, &msg_flags, &m_os, NULL); // Start an asynchronous read
		m_lastError = WSAGetLastError();
	}

	// If the timer has been invalidated, restart it
  if(m_recvEndTime == 0)
  {
    m_recvEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,m_recvTimeoutSeconds);
  }
	// Now wait for the I/O to complete if necessary, and see what happened
	bool IOCompleted = false;

	if ((received == SOCKET_ERROR) && (m_lastError == WSA_IO_PENDING))  // Read in progress, normal case
	{
		CTimeSpan TimeLeft = m_recvEndTime - CTime::GetCurrentTime();
		DWORD dwWait, milliSecondsLeft = (DWORD)TimeLeft.GetTotalSeconds()*1000;
    if(milliSecondsLeft <= 5)
    {
      dwWait = WAIT_TIMEOUT;
    }
		else
		{
			dwWait = WaitForMultipleObjects(2, hEvents, false, milliSecondsLeft);
      if(dwWait == WAIT_OBJECT_0 + 1) // The read event 
      {
        IOCompleted = true;
      }
		}
	}
  else if(!received) // if received is zero, the read was completed immediately
  {
    IOCompleted = true;
  }
	if (IOCompleted)
	{
		m_recvInitiated = false;
		if (WSAGetOverlappedResult(m_actualSocket, &m_os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
		{
      if(!InSecureMode())
      {
        DebugMsg(" ");
        DebugMsg("Received message has %d bytes",bytes_read);
        PrintHexDump(bytes_read,p_buffer);
      }

			m_lastError = 0;
      if(bytes_read == p_length) // We got what was requested
      {
        m_recvEndTime = 0; // Restart the timer on the next read
      }
			return bytes_read; // Normal case, we read some bytes, it's all good
		}
		else
		{	// A bad thing happened
			int error = WSAGetLastError();
      if(error == 0) // The socket was closed
      {
        return 0;
      }
      else if(m_lastError == 0)
      {
        m_lastError = error;
      }
		}
	}
	return SOCKET_ERROR;
}

// Receives exactly Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int PlainSocket::RecvMsg(LPVOID p_buffer, const ULONG p_length)
{
  ULONG bytes_received       = 0;
	ULONG total_bytes_received = 0; 

	m_recvEndTime = 0; // Tell RecvPartial to restart the timer

	while (total_bytes_received < p_length)
	{
		bytes_received = PlainSocket::RecvPartial((char*)p_buffer+total_bytes_received, p_length-total_bytes_received);
    if(bytes_received == SOCKET_ERROR)
    {
      return SOCKET_ERROR;
    }
    else if(bytes_received == 0)
    {
      break; // socket is closed, no data left to receive
    }
    else
    {
      total_bytes_received += bytes_received;
    }
	}; // loop
	return (total_bytes_received);
}

void PlainSocket::SetConnTimeoutSeconds(int p_newTimeoutSeconds)
{
  if(p_newTimeoutSeconds == INFINITE)
  {
    p_newTimeoutSeconds = MAXINT;
  }
  if(p_newTimeoutSeconds > 0)
  {
    m_connTimeoutSeconds = p_newTimeoutSeconds;
  }
}

void PlainSocket::SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds)
{
  if(NewRecvTimeoutSeconds == INFINITE)
  {
    NewRecvTimeoutSeconds = MAXINT;
  }
	if (NewRecvTimeoutSeconds>0)
	{
		m_recvTimeoutSeconds = NewRecvTimeoutSeconds;
		m_recvEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,m_recvTimeoutSeconds);
	}
}

void 
PlainSocket::SetSendTimeoutSeconds(int NewSendTimeoutSeconds)
{
  if(NewSendTimeoutSeconds == INFINITE)
  {
    NewSendTimeoutSeconds = MAXINT;
  }
	if (NewSendTimeoutSeconds>0)
	{
		m_sendTimeoutSeconds = NewSendTimeoutSeconds;
		m_sendEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,m_sendTimeoutSeconds);
	}
}

bool 
PlainSocket::SetUseKeepAlive(bool p_keepalive)
{
  m_useKeepalive = p_keepalive;
  if(m_initDone)
  {
    return ActivateKeepalive();
  }
  return true;
}

bool  
PlainSocket::SetKeepaliveTime(int p_time)
{
  if(p_time > MINIMUM_KEEPALIVE)
  {
    m_keepaliveTime = p_time;
    if(m_initDone)
    {
      return ActivateKeepalive();
    }
    return true;
  }
  return false;
}

bool  
PlainSocket::SetKeepaliveInterval(int p_interval)
{
  if(p_interval > MINIMUM_KEEPALIVE)
  {
    m_keepaliveInterval = p_interval;
    if(m_initDone)
    {
      return ActivateKeepalive();
    }
    return true;
  }
  return false;
}

DWORD PlainSocket::GetLastError()
{
	return m_lastError; 
}

// Shutdown one of the sides of the socket, or both
int 
PlainSocket::Disconnect(int p_how)
{
	return ::shutdown(m_actualSocket,p_how);
}

bool PlainSocket::Close(void)
{
  // Shutdown both sides of the socket
  if(Disconnect(SD_BOTH) == 0)
  {
    m_actualSocket = NULL;
    m_initDone     = false;
    return true;
  }
	else
	{
		m_lastError = ::WSAGetLastError();
		return false;
	}
}

// sends a message, or part of one
int PlainSocket::SendPartial(LPCVOID p_buffer, const ULONG p_length)
{
	WSAOVERLAPPED os;
	WSABUF buffer;
	DWORD bytes_sent = 0;

	// Setup the buffer array
	buffer.buf = (char *)p_buffer;
	buffer.len = p_length;


  if(!InSecureMode())
  {
    DebugMsg(" ");
    DebugMsg("Send message has %d bytes",p_length);
    PrintHexDump(p_length,p_buffer);
  }

	// Reset the timer if it has been invalidated 
  if(m_sendEndTime == 0)
  {
    m_sendEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,m_sendTimeoutSeconds);
  }
	m_lastError = 0;

	// Create the overlapped I/O event and structures
	memset(&os, 0, sizeof(OVERLAPPED));
	os.hEvent = m_write_event;
	WSAResetEvent(m_read_event);
	int received = WSASend(m_actualSocket, &buffer, 1, &bytes_sent, 0, &os, NULL);
	m_lastError  = WSAGetLastError();

	// Now wait for the I/O to complete if necessary, and see what happened
	bool IOCompleted = false;

	if ((received == SOCKET_ERROR) && (m_lastError == WSA_IO_PENDING))  // Write in progress
	{
		WSAEVENT hEvents[2] = {m_write_event, m_stopEvent};
	  DWORD dwWait;
		CTimeSpan TimeLeft = m_sendEndTime - CTime::GetCurrentTime();
		dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds()*1000);
    if(dwWait == WAIT_OBJECT_0 + 1) // The write event
    {
      IOCompleted = true;
    }
	}
  else if(!received) // if rc is zero, the write was completed immediately, which is common
  {
    IOCompleted = true;
  }

	if (IOCompleted)
	{
		DWORD msg_flags = 0;
		if (WSAGetOverlappedResult(m_actualSocket, &os, &bytes_sent, true, &msg_flags))
		{
      if(bytes_sent == p_length) // Everything that was requested was sent
      {
        m_sendEndTime = 0;  // Invalidate the timer so it is set next time through
      }
			return bytes_sent;
		}
	}
	return SOCKET_ERROR;
}

// sends all the data or returns a timeout
//
int
PlainSocket::SendMsg(LPCVOID p_buffer, const ULONG p_length)
{
	ULONG	bytes_sent       = 0;
	ULONG total_bytes_sent = 0;

  // Do we have something to do?
  if(p_length == 0)
  {
    return 0;
  }

	m_sendEndTime = 0; // Invalidate the timer so SendPartial can reset it.

	while (total_bytes_sent < p_length)
	{
		bytes_sent = PlainSocket::SendPartial((char*)p_buffer + total_bytes_sent, p_length - total_bytes_sent);
    if((bytes_sent == SOCKET_ERROR))
    {
      return SOCKET_ERROR;
    }
    else if(bytes_sent == 0)
    {
      if(total_bytes_sent == 0)
      {
        return SOCKET_ERROR;
      }
      else
      {
        break; // socket is closed, no chance of sending more
      }
    }
    else
    {
      total_bytes_sent += bytes_sent;
    }
	}; // loop
	return (total_bytes_sent);
}

// Test if the socket is (still) readable
bool
PlainSocket::IsReadible(bool& p_readible)
{
  timeval timeout = {0, 0};
  fd_set  fds;
  FD_ZERO(&fds);
  FD_SET(m_actualSocket,&fds);
  int status = select(0,&fds,nullptr,nullptr,&timeout);
  if(status == SOCKET_ERROR)
  {
    return false;
  }
  else
  {
    p_readible = !(status == 0);
    return true;
  }
}
