/////////////////////////////////////////////////////////////////////////////
// 
// SecureServerSocket
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "SecureServerSocket.h"
#include "SSLUtilities.h"
#include "SSLTracer.h"
#include "Logging.h"
#include "PlainSocket.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Global value to optimize access since it is set only once
PSecurityFunctionTable SecureServerSocket::g_pSSPI = NULL;

// Cached server credentials (a handle to a certificate), usually these do not change 
// because the server name does not change, but occasionally they may change due to SNI
CredHandle SecureServerSocket::g_ServerCreds = { 0 };
CString    SecureServerSocket::g_ServerName  = CString();

// The SecureServerSocket class, this declares an SSL server side implementation that requires
// some means to send messages to a client (a CPassiveSock).
//SecureServerSocket::SecureServerSocket(CPassiveSock * p_socketStream)
SecureServerSocket::SecureServerSocket(SOCKET p_socket,HANDLE p_stopEvent)
                   :PlainSocket(p_socket,p_stopEvent)
                   ,m_readPointer(m_readBuffer)
{
	m_context.dwLower = 
  m_context.dwUpper = ((ULONG_PTR) ((INT_PTR)-1)); // Invalidate it
}

SecureServerSocket::~SecureServerSocket(void)
{
  if(m_context.dwUpper != ((ULONG_PTR)((INT_PTR)-1)))
  {
    g_pSSPI->DeleteSecurityContext(&m_context);
  }
}

// Avoid using (or exporting) g_pSSPI directly to give us some flexibility in case we want
// to change implementation later
PSecurityFunctionTable SecureServerSocket::SSPI(void)
{
  return g_pSSPI;
}

// Return an ISocketStream interface to the SSL connection to anyone that needs one
// ISocketStream* SecureServerSocket::getSocketStream(void)
// {
// 	return m_SocketStream; // for now, return 'this' later, once we can do SSL
// }

// Set up the connection, including SSL handshake, certificate selection/validation
HRESULT 
SecureServerSocket::InitializeSSL(const void* p_buffer, const int p_length)
{
	HRESULT hr = S_OK;
	SECURITY_STATUS scRet;

	if (!g_pSSPI)
	{
		hr = InitializeClass();
    if FAILED(hr)
    {
      return LogSSLInitError(hr);
    }
	}
	
	if (p_buffer && (p_length>0))
	{  
    // pre-load the IO buffer with whatever we already read
		m_readBufferBytes = p_length;
		memcpy_s(m_readBuffer, sizeof(m_readBuffer), p_buffer, p_length);
	}
  else
  {
    m_readBufferBytes = 0;
  }

  // From here on, we are in secure mode
  m_secureMode = true;
  
  // Perform SSL handshake
	if(!SSPINegotiateLoop())
	{
		LogError("Couldn't negotiate SSL/TLS");
    if(IsUserAdmin())
    {
      LogError("SSL handshake failed");
    }
    else
    {
      LogError("SSL handshake failed, perhaps because you are not running as administrator.");
    }
    m_secureMode = false;
    int le = GetLastError();
		return LogSSLInitError(le == 0 ? E_FAIL : HRESULT_FROM_WIN32(le));
	}

	// Find out how big the header and trailer will be:

	scRet = g_pSSPI->QueryContextAttributes(&m_context, SECPKG_ATTR_STREAM_SIZES, &m_sizes);

	if(scRet != SEC_E_OK)
	{
    m_secureMode = false;
		LogError("Couldn't get crypt container sizes");
		return LogSSLInitError(E_FAIL);
	}

  return S_OK;
}

// Establish SSPI pointer
HRESULT 
SecureServerSocket::InitializeClass(void)
{
  g_pSSPI = InitSecurityInterface();

  if(g_pSSPI == NULL)
  {
		int err = ::GetLastError();
    if(err == 0)
    {
      return E_FAIL;
    }
    else
    {
      return HRESULT_FROM_WIN32(err);
    }
  }
  return S_OK;
}

HRESULT
SecureServerSocket::LogSSLInitError(HRESULT hr)
{
	if(FAILED(hr))
	{
    // ServerSocket will have m_secureMode = false
		int err = GetLastError();
    switch(hr)
    {
      case CRYPT_E_NOT_FOUND:         LogError("A usable SSL certificate could not be found");
                                      break;
      case SEC_E_CERT_UNKNOWN:        LogError("The returned client certificate was unacceptable");
                                      break;
      case SEC_E_INVALID_TOKEN:       LogError("SSL token invalid, perhaps the client rejected our certificate");
                                      break;
      case SEC_E_UNKNOWN_CREDENTIALS: LogError("Credentials unknown, is this program running with administrative privileges?");
                                      break;
      case E_ACCESSDENIED:            LogError("Could not access certificate store, is this program running with administrative privileges?");
                                      break;
	    default:                        LogError("SSL could not be used, hr=0x%lx, lasterror=0x%lx", hr, err);
                                      break;
		}
	}
  return hr;
}

// Receive an encrypted message, decrypt it, and return the resulting plaintext
int SecureServerSocket::RecvPartial(LPVOID p_buffer,const ULONG p_length)
{
  // If not in Secure SSL/TLS mode, pass on the the plain socket
  if(!InSecureMode())
  {
    return PlainSocket::RecvPartial(p_buffer,p_length);
  }

  // Secure receive after this point
	INT err;
	INT i;
	SecBufferDesc   Message;
	SecBuffer       Buffers[4];
	SECURITY_STATUS scRet;

	//
	// Initialize security buffer structs, basically, these point to places to put encrypted data,
	// for SSL there's a header, some encrypted data, then a trailer. All three get put in the same buffer
	// (ReadBuffer) and then decrypted. So one SecBuffer points to the header, one to the data, and one to the trailer.
	//
	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;

	Buffers[0].BufferType = SECBUFFER_EMPTY;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

  if(m_readBufferBytes == 0)
  {
    scRet = SEC_E_INCOMPLETE_MESSAGE;
  }
	else
	{	
    // There is already data in the buffer, so process it first
		DebugMsg(" ");
		DebugMsg("Using the saved %d bytes from client", m_readBufferBytes);
		PrintHexDump(m_readBufferBytes, m_readPointer);
		Buffers[0].pvBuffer = m_readPointer;
		Buffers[0].cbBuffer = m_readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;
		scRet = g_pSSPI->DecryptMessage(&m_context, &Message, 0, NULL);
	}

	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		err = PlainSocket::RecvPartial((CHAR*)m_readPointer + m_readBufferBytes,(int)( sizeof(m_readBuffer) - m_readBufferBytes - ((CHAR*)m_readPointer - &m_readBuffer[0])));
    m_lastError = 0; // Means use the one from m_SocketStream
		if ((err == SOCKET_ERROR) || (err == 0))
		{
      if(WSA_IO_PENDING == GetLastError())
      {
        LogError("Recv timed out");
      }
      else if(WSAECONNRESET == GetLastError())
      {
        LogError("Recv failed, the socket was closed by the other side");
      }
      else
      {
        LogError("Recv failed: %ld",GetLastError());
      }
			return SOCKET_ERROR;
		}
		DebugMsg(" ");
		DebugMsg("Received %d (request) bytes from client", err);
		PrintHexDump(err, (CHAR*)m_readPointer + m_readBufferBytes);
		m_readBufferBytes += err;

		Buffers[0].pvBuffer = m_readPointer;
		Buffers[0].cbBuffer = m_readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		scRet = g_pSSPI->DecryptMessage(&m_context, &Message, 0, NULL);
	}
	

  if(scRet == SEC_E_OK)
  {
    DebugMsg("Decrypted message from client.");
  }
	else
	{
		LogError("Couldn't decrypt, error %lx", scRet);
		m_lastError = scRet;
		return SOCKET_ERROR;
	}

	// Locate the data buffer because the decrypted data is placed there. It's almost certainly
	// the second buffer (index 1) and we start there, but search all but the first just in case...
	PSecBuffer pDataBuffer(NULL);

	for(i = 1; i < 4; i++)
	{
		if(Buffers[i].BufferType == SECBUFFER_DATA)
		{
			pDataBuffer = &Buffers[i];
			break;
		}
	}

	if(!pDataBuffer)
	{
		LogError("No data returned");
		m_lastError = WSASYSCALLFAILURE;
		return SOCKET_ERROR;
	}
	DebugMsg(" ");
	DebugMsg("Decrypted message has %d bytes", pDataBuffer->cbBuffer);
	PrintHexDump(pDataBuffer->cbBuffer, pDataBuffer->pvBuffer);

	// Move the data to the output stream

  if(p_length >= int(pDataBuffer->cbBuffer))
  {
    memcpy_s(p_buffer,p_length,pDataBuffer->pvBuffer,pDataBuffer->cbBuffer);
  }
	else
	{	// More bytes were decoded than the caller requested, so return an error
		m_lastError = WSAEMSGSIZE;
		return SOCKET_ERROR;
	}

	// See if there was any extra data read beyond what was needed for the message we are handling
	// TCP can sometime merge multiple messages into a single one, if there is, it will amost 
	// certainly be in the fourth buffer (index 3), but search all but the first, just in case.
	PSecBuffer pExtraDataBuffer(NULL);

	for(i = 1; i < 4; i++)
	{
		if(Buffers[i].BufferType == SECBUFFER_EXTRA)
		{
			pExtraDataBuffer = &Buffers[i];
			break;
		}
	}

	if(pExtraDataBuffer)
	{	
    // More data was read than is needed, this happens sometimes with TCP
		DebugMsg(" ");
		DebugMsg("Some extra ciphertext was read (%d bytes)", pExtraDataBuffer->cbBuffer);
		// Remember where the data is for next time
		m_readBufferBytes = pExtraDataBuffer->cbBuffer;
		m_readPointer = pExtraDataBuffer->pvBuffer;
	}
	else
	{
		DebugMsg("No extra ciphertext was read");
		m_readBufferBytes = 0;
		m_readPointer = m_readBuffer;
	}
	
	return pDataBuffer->cbBuffer;
}

// Send an encrypted message containing an encrypted version of 
// whatever plaintext data the caller provides
int SecureServerSocket::SendPartial(LPCVOID p_buffer, const ULONG p_length)
{
  if(!p_buffer || p_length > m_maxMsgSize)
  {
    return SOCKET_ERROR;
  }

  // If not in SSL/TLS mode: pass on the the insecure plain socket
  if(!InSecureMode())
  {
    return PlainSocket::SendPartial(p_buffer,p_length);
  }

  INT err;

	SecBufferDesc   Message;
	SecBuffer       Buffers[4];
	SECURITY_STATUS scRet;

	//
	// Initialize security buffer structs
	//
	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;

	Buffers[0].BufferType = SECBUFFER_EMPTY;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

	// Put the message in the right place in the buffer
	memcpy_s(m_writeBuffer + m_sizes.cbHeader, sizeof(m_writeBuffer) - m_sizes.cbHeader - m_sizes.cbTrailer, p_buffer, p_length);

	//
	// Line up the buffers so that the header, trailer and content will be
	// all positioned in the right place to be sent across the TCP connection as one message.
	//

	Buffers[0].pvBuffer = m_writeBuffer;
	Buffers[0].cbBuffer = m_sizes.cbHeader;
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	Buffers[1].pvBuffer = m_writeBuffer + m_sizes.cbHeader;
	Buffers[1].cbBuffer = p_length;
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer = m_writeBuffer + m_sizes.cbHeader + p_length;
	Buffers[2].cbBuffer = m_sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].BufferType = SECBUFFER_EMPTY;

	scRet = g_pSSPI->EncryptMessage(&m_context, 0, &Message, 0);

	DebugMsg(" ");
	DebugMsg("Plaintext message has %d bytes", p_length);
	PrintHexDump(p_length, p_buffer);

	if (FAILED(scRet))
	{
		LogError("EncryptMessage failed with %#x", scRet );
		m_lastError = scRet;
		return SOCKET_ERROR;
	}

	err = PlainSocket::SendPartial(m_writeBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_lastError = 0;

	DebugMsg("Send %d encrypted bytes to client", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	PrintHexDump(Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, m_writeBuffer);
	if (err == SOCKET_ERROR)
	{
		LogError("Send failed: %ld",GetLastError());
		return SOCKET_ERROR;
	}
	return p_length;
}

// Negotiate a connection with the client, sending and receiving messages until the
// negotiation succeeds or fails
bool SecureServerSocket::SSPINegotiateLoop(void)
{
	TimeStamp       tsExpiry;
	SECURITY_STATUS scRet;
	SecBufferDesc   InBuffer;
	SecBufferDesc   OutBuffer;
	SecBuffer       InBuffers[2];
	SecBuffer       OutBuffers[1];
	DWORD           err = 0;
	DWORD           dwSSPIOutFlags = 0;
	bool						ContextHandleValid = (m_context.dwUpper != ((ULONG_PTR) ((INT_PTR)-1))); 

	DWORD dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT  |
		                  ASC_REQ_REPLAY_DETECT    |
		                  ASC_REQ_CONFIDENTIALITY  |
		                  ASC_REQ_EXTENDED_ERROR   |
		                  ASC_REQ_ALLOCATE_MEMORY  |
		                  ASC_REQ_STREAM;

   if (m_clientCertAcceptable) // If the caller wants a client certificate, request one
   {
      DebugMsg("Client-certificate will be required.");
      dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;
   }
   else
   {
     DebugMsg("NO Client-certificate will be requested.");
   }

	//
	//  set OutBuffer for InitializeSecurityContext call
	//

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	DebugMsg("Started SSPINegotiateLoop with %d bytes already received from client.", m_readBufferBytes);

	scRet = SEC_E_INCOMPLETE_MESSAGE;

	// Main loop, keep going around this until the handshake is completed or fails
	while( scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_INCOMPLETE_MESSAGE || scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
	{
		if (m_readBufferBytes == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{	
      // Read some more bytes if available, we may read more than is needed for this phase of handshake 
			err = PlainSocket::RecvPartial(m_readBuffer + m_readBufferBytes, sizeof(m_readBuffer) - m_readBufferBytes);
			m_lastError = 0;
			if (err == SOCKET_ERROR || err == 0)
			{
        if(WSA_IO_PENDING == GetLastError())
        {
          LogError("Recv timed out");
        }
        else if(WSAECONNRESET == GetLastError())
        {
          LogError("Recv failed, the socket was closed by the other host");
        }
        else
        {
          LogError("Recv failed: %d",GetLastError());
        }
				return false;
			}
			else
			{
				m_readBufferBytes += err;
				DebugMsg(" ");
        if(err == m_readBufferBytes)
        {
          DebugMsg("Received %d handshake bytes from client",err);
        }
        else
        {
          DebugMsg("Received %d handshake bytes from client, total is now %d ",err,m_readBufferBytes);
        }
        SSLTracer tracer((const byte*)m_readBuffer, m_readBufferBytes);
        tracer.TraceHandshake();
        if (tracer.IsClientInitialize())
        {  
          // Figure out what certificate we might want to use, either using SNI or the local host name
          CString serverName = tracer.GetSNIHostname();
          if ((!g_ServerCreds.dwLower && !g_ServerCreds.dwUpper) // No certificate handle stored
            || (serverName.Compare(g_ServerName) != 0)) // Requested names are different
          {  // 
            if((g_ServerCreds.dwLower || g_ServerCreds.dwUpper)) // Certificate handle stored
            {
              g_pSSPI->FreeCredentialsHandle(&g_ServerCreds);
            }
            if(serverName.IsEmpty()) // There was no hostname supplied by SNI
            {
              serverName = GetHostName(ComputerNameDnsHostname);
            }
            PCCERT_CONTEXT pCertContext = NULL;
            SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
            if (m_selectServerCert)
            {
              status = m_selectServerCert(pCertContext, (LPCTSTR)serverName);
              if (FAILED(status))
              {
                LogError("SelectServerCert returned an error = 0x%08x", status);
                scRet = SEC_E_INTERNAL_ERROR;
                break;
              }
            }
            else
            {
              // Add "true" to look in user store, "false", or nothing looks in machine store
              status = CertFindServerByName(pCertContext,(LPCTSTR)serverName,false);
            }
            g_ServerName = (SUCCEEDED(status)) ? serverName : CString();
            if(SUCCEEDED(status))
            {
              status = CreateCredentialsFromCertificate(&g_ServerCreds,pCertContext);
            }
            if (FAILED(status))
            {
              LogError("Failed handling server initialization, error = 0x%08x", status);
              scRet = SEC_E_INTERNAL_ERROR;
              break;
            }
          }
        }
			}
		}

		//
		// InBuffers[1] is used for storing extra data that SSPI/SCHANNEL doesn't process on this run around the loop.
		//
    // Set up the input buffers. Buffer 0 is used to pass in data
    // received from the server. Schannel will consume some or all
    // of this. Leftover data (if any) will be placed in buffer 1 and
    // given a buffer type of SECBUFFER_EXTRA.
    //

		InBuffers[0].pvBuffer = m_readBuffer;
		InBuffers[0].cbBuffer = m_readBufferBytes;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer   = NULL;
		InBuffers[1].cbBuffer   = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;

		InBuffer.cBuffers        = 2;
		InBuffer.pBuffers        = InBuffers;
		InBuffer.ulVersion       = SECBUFFER_VERSION;

		//
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
		//

		OutBuffers[0].pvBuffer   = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer   = 0;

		scRet = g_pSSPI->AcceptSecurityContext(&g_ServerCreds								        // Which certificate to use, already established
			                                    ,ContextHandleValid?&m_context:NULL	// The context handle if we have one, ask to make one if this is first call
			                                    ,&InBuffer										        // Input buffer list
			                                    ,dwSSPIFlags									        // What we require of the connection
			                                    ,0													          // Data representation, not used 
			                                    ,ContextHandleValid?NULL:&m_context	// If we don't yet have a context handle, it is returned here
			                                    ,&OutBuffer										        // [out] The output buffer, for messages to be sent to the other end
			                                    ,&dwSSPIOutFlags								      // [out] The flags associated with the negotiated connection
			                                    ,&tsExpiry);										      // [out] Receives context expiration time

		ContextHandleValid = true;

		if(scRet == SEC_E_OK || 
       scRet == SEC_I_CONTINUE_NEEDED || 
       (FAILED(scRet) && (0 != (dwSSPIOutFlags & ASC_RET_EXTENDED_ERROR))))
		{
      if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
			{
				// Send response to client if there is one
		 // err = m_SocketStream->CPassiveSock::Send(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
        err = PlainSocket::SendPartial(OutBuffers[0].pvBuffer,OutBuffers[0].cbBuffer);
        m_lastError = 0;
				if (err == SOCKET_ERROR || err == 0)
				{
					LogError("Send handshake to client failed: %d",GetLastError() );
					g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					return false;
				}
				else
				{
					DebugMsg(" ");
					DebugMsg("Send %d handshake bytes to client", OutBuffers[0].cbBuffer);
					PrintHexDump(OutBuffers[0].cbBuffer, OutBuffers[0].pvBuffer);
				}
				g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = NULL;
			}
		}

		// At this point, we've read and checked a message (giving scRet) and maybe sent a response (giving err)
    // as far as the client is concerned, the SSL handshake may be done, but we still have checks to make.

		if (scRet == SEC_E_OK)
		{	
      // The termination case, the handshake worked and is completed, this could as easily be outside the loop
      // Ensure a client certificate is checked if one was requested, if none was provided we'd already have failed

      if (m_clientCertAcceptable)
      {
        PCERT_CONTEXT pCertContext = NULL;
        HRESULT hr = g_pSSPI->QueryContextAttributes(&m_context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCertContext);

        if(FAILED(hr))
        {
          LogError("Couldn't get client certificate, hr=%#x",hr);
        }
        else
        {
          DebugMsg("Client Certificate returned");
          if(SSL_socket_logging && pCertContext)
          {
            ShowCertInfo(pCertContext,"Server Received Client Certificate");
          }
          // All looking good, now see if there's a client certificate, and if it is valid
          bool acceptable = m_clientCertAcceptable(pCertContext, S_OK == CertTrusted(pCertContext));
          CertFreeCertificateContext(pCertContext);
          if(acceptable)
          {
            DebugMsg("Client certificate was acceptable");
          }
          else
          {
            LogError("Client certificate was unacceptable");
            return false;
          }
        }
      }

      // Now deal with the possibility that there were some data bytes tacked on to the end of the handshake
      if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
			{
				m_readPointer = m_readBuffer + (m_readBufferBytes - InBuffers[1].cbBuffer);
				m_readBufferBytes = InBuffers[1].cbBuffer;
				DebugMsg("Handshake worked, but received %d extra bytes", m_readBufferBytes);
			}
			else
			{
				m_readBufferBytes = 0;
				m_readPointer = m_readBuffer;
				DebugMsg("Handshake worked, no extra bytes received");
			}
			m_lastError = 0;
      // The normal exit
      return true; 
		}
		else if (scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			DebugMsg("AcceptSecurityContext got a partial message and is requesting more be read");
		}
		else if (scRet == SEC_E_INCOMPLETE_CREDENTIALS)
		{
			DebugMsg("AcceptSecurityContext got SEC_E_INCOMPLETE_CREDENTIALS, it shouldn't but we'll treat it like a partial message");
		}
		else if (FAILED(scRet))
		{
      if(scRet == SEC_E_INVALID_TOKEN)
      {
        LogError("AcceptSecurityContext detected an invalid token, maybe the client rejected our certificate");
      }
      else
      {
        LogError("AcceptSecurityContext Failed with error code %lx",scRet);
      }
			m_lastError = scRet;
			return false;
		}
		else
		{  
      // We won't be appending to the message data already in the buffer, so store a reference to any extra data in case it is useful
			if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
			{
				m_readPointer = m_readBuffer + (m_readBufferBytes - InBuffers[1].cbBuffer);
				m_readBufferBytes = InBuffers[1].cbBuffer;
				DebugMsg("Handshake working so far but received %d extra bytes we can't handle", m_readBufferBytes);
				m_lastError = WSASYSCALLFAILURE;
				return false;
			}
			else
			{
				m_readPointer = m_readBuffer;
				m_readBufferBytes = 0; // prepare for next receive
				DebugMsg("Handshake working so far, more packets required");
			}
		}
	} // while loop

	// Something is wrong, we exited the loop abnormally
	LogError("Unexpected security return value %lx", scRet);
	m_lastError = scRet;
	return false;
}

bool
SecureServerSocket::Close(void)
{
  // Shutdown both sides of the socket
  return Disconnect(SD_BOTH) == 0;
}

// In theory a connection may switch in and out of SSL mode.
// This stops SSL, but it has not been tested
int
SecureServerSocket::Disconnect(int p_how /*=SD_BOTH*/)
{
  // In plain mode, do the socket disconnect
  if(!InSecureMode())
  {
    return PlainSocket::Disconnect(p_how);
  }

  // Prepare for secure disconnect
	DWORD           dwType;
	PBYTE           pbMessage;
	DWORD           cbMessage;
	DWORD           cbData;

	SecBufferDesc   OutBuffer;
	SecBuffer       OutBuffers[1];
	DWORD           dwSSPIFlags;
	DWORD           dwSSPIOutFlags;
	TimeStamp       tsExpiry;
	DWORD           Status;

	//
	// Notify schannel that we are about to close the connection.
	//

	dwType = SCHANNEL_SHUTDOWN;

	OutBuffers[0].pvBuffer   = &dwType;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer   = sizeof(dwType);

	OutBuffer.cBuffers  = 1;
	OutBuffer.pBuffers  = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->ApplyControlToken(&m_context, &OutBuffer);

	if(FAILED(Status)) 
	{
		LogError("**** Error 0x%x returned by ApplyControlToken", Status);
		return Status;
	}

	//
	// Build an SSL close notify message.
	//

	dwSSPIFlags =   
		ASC_REQ_SEQUENCE_DETECT     |
		ASC_REQ_REPLAY_DETECT       |
		ASC_REQ_CONFIDENTIALITY     |
		ASC_REQ_EXTENDED_ERROR      |
		ASC_REQ_ALLOCATE_MEMORY     |
		ASC_REQ_STREAM;

	OutBuffers[0].pvBuffer   = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer   = 0;

	OutBuffer.cBuffers  = 1;
	OutBuffer.pBuffers  = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->AcceptSecurityContext(&g_ServerCreds		// Which certificate to use, already established
		                                     ,&m_context				// The context handle if we have one, ask to make one if this is first call
		                                     ,NULL							// Input buffer list
		                                     ,dwSSPIFlags				// What we require of the connection
		                                     ,0								  // Data representation, not used 
		                                     ,NULL							// Returned context handle, not used, because we already have one
		                                     ,&OutBuffer				// [out] The output buffer, for messages to be sent to the other end
		                                     ,&dwSSPIOutFlags		// [out] The flags associated with the negotiated connection
		                                     ,&tsExpiry);				// [out] Receives context expiration time

	if(FAILED(Status)) 
	{
		LogError("**** Error 0x%x returned by AcceptSecurityContext", Status);
		return Status;
	}

	pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
	cbMessage = OutBuffers[0].cbBuffer;

	//
	// Send the close notify message to the client.
	//

	if(pbMessage != NULL && cbMessage != 0)
	{
		cbData = PlainSocket::SendPartial(pbMessage, cbMessage);
		if(cbData == SOCKET_ERROR || cbData == 0)
		{
			Status = GetLastError();
			LogError("**** Error %d sending close notify", Status);
			return HRESULT_FROM_WIN32(Status);
		}

		DebugMsg(" ");
		DebugMsg("%d bytes of data sent to notify SCHANNEL_SHUTDOWN", cbData);
		PrintHexDump(cbData, pbMessage);
	}
	PlainSocket::Disconnect();
	return S_OK;	 
}

// Create credentials (a handle to a certificate) by selecting an appropriate certificate
// We take a best guess at a certificate to be used as the SSL certificate for this server 
SECURITY_STATUS 
SecureServerSocket::CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
{
   // Build SCHANNEL credential structure.
   SCHANNEL_CRED   SchannelCred = { 0 };
   SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
   SchannelCred.cCreds    = 1;
   SchannelCred.paCred    = &pCertContext;
   SchannelCred.dwFlags   = SCH_USE_STRONG_CRYPTO;
   SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;

   SECURITY_STATUS Status;
   TimeStamp       tsExpiry;
   // Get a handle to the SSPI credential
   Status = g_pSSPI->AcquireCredentialsHandle(NULL,                   // Name of principal
                                              UNISP_NAME,             // Name of package
                                              SECPKG_CRED_INBOUND,    // Flags indicating use
                                              NULL,                   // Pointer to logon ID
                                              &SchannelCred,          // Package specific data
                                              NULL,                   // Pointer to GetKey() func
                                              NULL,                   // Value to pass to GetKey()
                                              phCreds,                // (out) Cred Handle
                                              &tsExpiry);             // (out) Lifetime (optional)

   if (Status != SEC_E_OK)
   {
      DWORD dw = GetLastError();
      if(Status == SEC_E_UNKNOWN_CREDENTIALS)
      {
        LogError("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. Be sure app has administrator rights. LastError=%d",dw);
      }
      else
      {
        LogError("**** Error 0x%x returned by AcquireCredentialsHandle. LastError=%d.",Status,dw);
      }
      return Status;
   }
   return SEC_E_OK;
}

// sends all the data or returns a timeout
//
int
SecureServerSocket::SendMsg(LPCVOID p_buffer,const ULONG p_length)
{
  ULONG	bytes_sent = 0;
  ULONG total_bytes_sent = 0;

  // Do we have something to do?
  if(p_length == 0)
  {
    return 0;
  }

  while(total_bytes_sent < p_length)
  {
    bytes_sent = SecureServerSocket::SendPartial((char*)p_buffer + total_bytes_sent,p_length - total_bytes_sent);
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
  }

  return (total_bytes_sent);
}

// Receives exactly Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int
SecureServerSocket::RecvMsg(LPVOID p_buffer,const ULONG p_length)
{
  ULONG bytes_received = 0;
  ULONG total_bytes_received = 0;

  while(total_bytes_received < p_length)
  {
    bytes_received = SecureServerSocket::RecvPartial((char*)p_buffer + total_bytes_received,p_length - total_bytes_received);
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
  }

  return (total_bytes_received);
}
