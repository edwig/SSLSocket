/////////////////////////////////////////////////////////////////////////////
// 
// SecureClientSocket
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "SecureClientSocket.h"
#include "SSLUtilities.h"
#include "PlainSocket.h"
#include "SecurityHandle.h"
#include "Logging.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Global value to optimize access since it is set only once
PSecurityFunctionTable SecureClientSocket::g_pSSPI = NULL;

// The CSSLClient class, this declares an SSL client side implementation that requires
// some means to send messages to a server (a CActiveSock).
SecureClientSocket::SecureClientSocket(HANDLE p_stopEvent)
                   :PlainSocket(p_stopEvent)
{
  m_readPointer  = m_readBuffer;
}

SecureClientSocket::~SecureClientSocket(void)
{
}

// Avoid using (or exporting) g_pSSPI directly to give us some flexibility in case we want
// to change implementation later
PSecurityFunctionTable 
SecureClientSocket::SSPI(void)
{
  return g_pSSPI;
}

// Set up for a SSL protection level
void    
SecureClientSocket::SetSSLProtectionLevel(SSLProtClass p_class)
{
  m_sslClass = p_class;
}

// Set up the connection, including SSL handshake, certificate selection/validation
// lpBuf and Len let you provide any data that's already been read
HRESULT 
SecureClientSocket::InitializeSSL(const void* p_buffer, const int p_length)
{
	HRESULT hr = S_OK;
	m_serverCertNameMatches = false;
	m_serverCertTrusted     = false;

  // If not already initialized by another socket
	if (!g_pSSPI)
	{
		hr = InitializeSecurityInterface();
    if(FAILED(hr))
    {
      return hr;
    }
	}
	ConstCertContextHandle hCertContext;
  if(m_selectClientCertificate)
  {
    hr = m_selectClientCertificate(setref(hCertContext),NULL,false);
  }
  // If a certificate is required, it will be requested later 
  hr = CreateCredentialsFromCertificate(set(m_clientCredentials), get(hCertContext));
  if(FAILED(hr))
  {
    return hr;
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

  // From now on, we are in secure SSL/TLS mode
  m_secureMode = true;

  // Perform SSL handshake
  hr = SSPINegotiateLoop((TCHAR*) m_hostName.GetString());
	if(FAILED(hr))
	{
		LogError("Couldn't negotiate SSL/TLS");
    m_secureMode = false;
		return hr;
	}

	// Find out how big the header and trailer will be:
	hr = g_pSSPI->QueryContextAttributes(&get(m_context), SECPKG_ATTR_STREAM_SIZES, &m_sizes);

	if(FAILED(hr))
	{
		LogError("Couldn't get stream sizes, hr=%#x", hr);
    m_secureMode = false;
		return hr;
	}

	return S_OK;
}

// Establish SSPI pointer and correct credentials (meaning pick a certificate) for the SSL server
HRESULT 
SecureClientSocket::InitializeSecurityInterface(void)
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

// Because SSL is message oriented these calls send (or receive) a whole message
int 
SecureClientSocket::RecvPartial(LPVOID p_buffer, const ULONG p_length)
{
  if (m_plainTextBytes > 0)
  {	
    // There are stored bytes, just return them
	  DebugMsg("There is cached plaintext %d bytes", m_plainTextBytes);
    if(false)
    {
      PrintHexDump(m_plainTextBytes,m_plainTextPtr);
    }
	  // Move the data to the output stream

	  if (p_length >= m_plainTextBytes)
	  {
		  int bytesReturned = m_plainTextBytes;
      DebugMsg("All %d cached plaintext bytes can be returned", m_plainTextBytes);
      if(false)
      {
        PrintHexDump(m_plainTextBytes,m_plainTextPtr);
      }
		  memcpy_s(p_buffer, p_length, m_plainTextPtr, m_plainTextBytes);
      m_plainTextBytes = 0;
		  return bytesReturned;
	  }
	  else
	  {	
      // More bytes are stored than the caller requested, so return some, store the rest until the next call
		  memcpy_s(p_buffer, p_length, m_plainTextPtr, p_length);
		  m_plainTextPtr   += p_length;
      m_plainTextBytes -= p_length;
		  DebugMsg("%d cached plaintext bytes can be returned, %d remain", p_length, m_plainTextBytes);
      if(false)
      {
        PrintHexDump(m_plainTextBytes,m_plainTextPtr);
      }
		  return p_length;
	  }
  }

  // plainTextBytes == 0 at this point

  // If not in Secure SSL/TLS mode, pass on the the plain socket
  if(!InSecureMode())
  {
    return PlainSocket::RecvPartial(p_buffer,p_length);
  }

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
	Message.cBuffers  = 4;
	Message.pBuffers  = Buffers;

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
		DebugMsg("Using the saved %d bytes from server", m_readBufferBytes);
		if (false) PrintHexDump(m_readBufferBytes, m_readPointer);
		Buffers[0].pvBuffer   = m_readPointer;
		Buffers[0].cbBuffer   = m_readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;
		scRet = g_pSSPI->DecryptMessage(&get(m_context), &Message, 0, NULL);
	}

	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
    int freeBytesAtStart = static_cast<int>((CHAR*)m_readPointer - &m_readBuffer[0]); 
    int freeBytesAtEnd   = static_cast<int>(sizeof(m_readBuffer)) - m_readBufferBytes - freeBytesAtStart;

    // There is no space to add more at the end of the buffer
    if (freeBytesAtEnd == 0) 
    {
      if (freeBytesAtStart > 0) // which ought to always be true at this point
      {
        // Move down the existing data to make room for more at the end of the buffer
        memmove_s(m_readBuffer, sizeof(m_readBuffer), m_readPointer, static_cast<int>(sizeof(m_readBuffer)) - freeBytesAtStart);
        freeBytesAtEnd = freeBytesAtStart;
        m_readPointer = m_readBuffer;
      }
      else
      {
			  LogError("RecvMsg Buffer inexplicably full");
			  return SOCKET_ERROR;
      }
    }
    err = PlainSocket::RecvPartial((CHAR*)m_readPointer + m_readBufferBytes, freeBytesAtEnd);
		m_lastError = 0; // Means use the one from m_SocketStream
		if ((err == SOCKET_ERROR) || (err == 0))
		{
      if(WSA_IO_PENDING == GetLastError())
      {
        LogError("RecvMsg timed out");
      }
      else if(WSAECONNRESET == GetLastError())
      {
        LogError("RecvMsg failed, the socket was closed by the other host");
      }
      else
      {
        LogError("RecvMsg failed: %ld",GetLastError());
      }
			return SOCKET_ERROR;
		}
		DebugMsg(" ");
		DebugMsg("Received %d bytes of ciphertext from server", err);
    PrintHexDump(err,(CHAR*)m_readPointer + m_readBufferBytes);

    m_readBufferBytes += err;

		Buffers[0].pvBuffer   = m_readPointer;
		Buffers[0].cbBuffer   = m_readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		scRet = g_pSSPI->DecryptMessage(&get(m_context), &Message, 0, NULL);
	}
	
  if(scRet == SEC_E_OK)
  {
    DebugMsg("Decrypted message from server.");
  }
	else if(scRet == SEC_I_CONTEXT_EXPIRED)
	{
    DebugMsg("Server signaled end of session");
		m_lastError = scRet;
		return SOCKET_ERROR;
	}
	else
	{
		LogError("Couldn't decrypt data from server, error %lx", scRet);
		m_lastError = scRet;
		return SOCKET_ERROR;
	}
	// There's a legitimate case here of a server wanting to renegotiate the session
	// by returning SEC_I_RENEGOTIATE. This code does not support it.

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
  PrintHexDump(pDataBuffer->cbBuffer,pDataBuffer->pvBuffer);

	// Move the data to the output stream

  if(p_length >= int(pDataBuffer->cbBuffer))
  {
    memcpy_s(p_buffer,p_length,pDataBuffer->pvBuffer,pDataBuffer->cbBuffer);
  }
	else
	{	
    // More bytes were decoded than the caller requested, so return some, store the rest until the next call
		memcpy_s(p_buffer, p_length, pDataBuffer->pvBuffer, p_length);
		m_plainTextBytes = pDataBuffer->cbBuffer - p_length;
      m_plainTextPtr = m_plainText;
   	DebugMsg("Extra %d plaintext bytes stored", m_plainTextBytes);
		if (memcpy_s(m_plainText, sizeof(m_plainText), (char*)pDataBuffer->pvBuffer + p_length, m_plainTextBytes))
		{
   		m_lastError = WSAEMSGSIZE;
   		return SOCKET_ERROR;
		}
    else
    {
      // Pretend we only saw Len bytes
      pDataBuffer->cbBuffer = p_length; 
    }
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
	{	// More data was read than is needed, this happens sometimes with TCP
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
} // ReceivePartial

// Send an encrypted message containing an encrypted version of 
// whatever plaintext data the caller provides
//
int SecureClientSocket::SendPartial(LPCVOID p_buffer, const ULONG p_length)
{
  if(!p_buffer || p_length > MaxMsgSize)
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
	// Initialize security buffer struct
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

	Buffers[0].pvBuffer   = m_writeBuffer;
	Buffers[0].cbBuffer   = m_sizes.cbHeader;
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	Buffers[1].pvBuffer   = m_writeBuffer + m_sizes.cbHeader;
	Buffers[1].cbBuffer   = p_length;
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer   = m_writeBuffer + m_sizes.cbHeader + p_length;
	Buffers[2].cbBuffer   = m_sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].BufferType = SECBUFFER_EMPTY;

	scRet = g_pSSPI->EncryptMessage(&get(m_context), 0, &Message, 0);

	DebugMsg(" ");
	DebugMsg("Plaintext message has %d bytes", p_length);
	PrintHexDump(p_length, p_buffer);

	if (FAILED(scRet))
	{
		LogError("EncryptMessage failed with %#x", scRet );
		m_lastError = scRet;
		return SOCKET_ERROR;
	}

	err = PlainSocket::SendMsg(m_writeBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_lastError = 0;

	DebugMsg("SendPartial %d encrypted bytes to server", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	PrintHexDump(Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, m_writeBuffer);
	
  if (err == SOCKET_ERROR)
	{
		LogError( "SendPartial failed: %ld", GetLastError());
		return SOCKET_ERROR;
	}
	return p_length;
} // SendPartial

// Negotiate a connection with the server, sending and receiving messages until the
// negotiation succeeds or fails
SECURITY_STATUS 
SecureClientSocket::SSPINegotiateLoop(TCHAR* ServerName)
{
	int               cbData;
	TimeStamp         tsExpiry;
	SECURITY_STATUS   scRet;
	SecBufferDesc     InBuffer;
	SecBufferDesc     OutBuffer;
	SecBuffer         InBuffers[2];
	SecBuffer         OutBuffers[1];
	DWORD             err = 0;
	DWORD             dwSSPIFlags = 0;

  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                ISC_REQ_REPLAY_DETECT     |
                ISC_REQ_CONFIDENTIALITY   |
                ISC_REQ_EXTENDED_ERROR    |
                ISC_REQ_ALLOCATE_MEMORY   |
						    ISC_REQ_MANUAL_CRED_VALIDATION | // We'll check the certificate ourselves
                ISC_REQ_STREAM;

  //
  //  Initiate a ClientHello message and generate a token.
  //

  OutBuffers[0].pvBuffer   = NULL;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = 0;

  OutBuffer.cBuffers = 1;
  OutBuffer.pBuffers = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  scRet = g_pSSPI->InitializeSecurityContext(
		                   &get(m_clientCredentials),
		                   NULL,
		                   ServerName,
		                   dwSSPIFlags,
		                   0,
		                   SECURITY_NATIVE_DREP,
		                   NULL,
		                   0,
		                   set(m_context),
		                   &OutBuffer,
		                   &dwSSPIFlags,
		                   &tsExpiry);

  if(scRet != SEC_I_CONTINUE_NEEDED)
  {
		LogError("**** Error %#x returned by InitializeSecurityContext (1)", scRet);
    return scRet;
  }

  // Send response to server if there is one.
  if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
  {
	  cbData = PlainSocket::SendMsg(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
    if(cbData != OutBuffers[0].cbBuffer)
    {
      LogError("**** Error %d sending data to server (1)", WSAGetLastError());
      g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
		  m_context.Close();
      return SEC_E_INTERNAL_ERROR;
    }

    DebugMsg("%d bytes of handshake data sent", cbData);
    PrintHexDump(cbData, OutBuffers[0].pvBuffer);
    DebugMsg("\n");

    // Free output buffer.
    g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
    OutBuffers[0].pvBuffer = NULL;
  }

	// Now start loop to negotiate SSL 
  DWORD  dwSSPIOutFlags;
  DWORD  cbIoBuffer;
  BOOL   fDoRead;


  cbIoBuffer = 0;

  fDoRead = TRUE; // do an initial read

  // 
  // Loop until the handshake is finished or an error occurs.
  //

  while(scRet == SEC_I_CONTINUE_NEEDED        ||
        scRet == SEC_E_INCOMPLETE_MESSAGE     ||
        scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
  {
    //
    // Read data from server.
    //

    if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
    {
      if(fDoRead)
      {
				cbData = PlainSocket::RecvPartial(m_readBuffer + cbIoBuffer, sizeof(m_readBuffer) - cbIoBuffer);
        if(cbData == SOCKET_ERROR)
        {
          LogError("**** Error %d reading data from server", WSAGetLastError());
          scRet = SEC_E_INTERNAL_ERROR;
          break;
        }
        else if(cbData == 0)
        {
          LogError("**** Server unexpectedly disconnected");
          scRet = SEC_E_INTERNAL_ERROR;
          break;
        }

        DebugMsg("%d bytes of handshake data received", cbData);
        PrintHexDump(cbData, m_readBuffer + cbIoBuffer);
        DebugMsg("\n");

        cbIoBuffer += cbData;
      }
      else
      {
        fDoRead = TRUE;
      }
    }


    //
    // Set up the input buffers. Buffer 0 is used to pass in data
    // received from the server. SCHANNEL will consume some or all
    // of this. Leftover data (if any) will be placed in buffer 1 and
    // given a buffer type of SECBUFFER_EXTRA.
    //

    InBuffers[0].pvBuffer   = m_readBuffer;
    InBuffers[0].cbBuffer   = cbIoBuffer;
    InBuffers[0].BufferType = SECBUFFER_TOKEN;

    InBuffers[1].pvBuffer   = NULL;
    InBuffers[1].cbBuffer   = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    InBuffer.cBuffers       = 2;
    InBuffer.pBuffers       = InBuffers;
    InBuffer.ulVersion      = SECBUFFER_VERSION;

    //
    // Set up the output buffers. These are initialized to NULL
    // so as to make it less likely we'll attempt to free random
    // garbage later.
    //

    OutBuffers[0].pvBuffer  = NULL;
    OutBuffers[0].BufferType= SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer  = 0;

    OutBuffer.cBuffers      = 1;
    OutBuffer.pBuffers      = OutBuffers;
    OutBuffer.ulVersion     = SECBUFFER_VERSION;

    //
    // Call InitializeSecurityContext.
    //

    scRet = g_pSSPI->InitializeSecurityContext(&get(m_clientCredentials),
                                          &get(m_context),
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

    //
    // If InitializeSecurityContext was successful (or if the error was 
    // one of the special extended ones), send the contends of the output
    // buffer to the server.
    //

    if(scRet == SEC_E_OK                ||
       scRet == SEC_I_CONTINUE_NEEDED   ||
       FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
    {
      // Get the server supplied certificate in order to decide whether it is acceptable

      CertContextHandle hServerCertContext;

      HRESULT hr = g_pSSPI->QueryContextAttributes(&get(m_context), SECPKG_ATTR_REMOTE_CERT_CONTEXT, set(hServerCertContext));

      if (FAILED(hr))
      {
        if(hr == SEC_E_INVALID_HANDLE)
        {
          DebugMsg("QueryContextAttributes for cert returned SEC_E_INVALID_HANDLE, which is normal");
        }
        else
        {
          LogError("Couldn't get server certificate, hr=%#x",hr);
        }
      }
      else
      {
        DebugMsg("Server Certificate returned");
        m_serverCertNameMatches = MatchCertHostName(get(hServerCertContext),ServerName);
        hr = CertTrusted(get(hServerCertContext));
        m_serverCertTrusted = hr == S_OK;
        bool IsServerCertAcceptable = m_serverCertAcceptable == nullptr;
        if(!IsServerCertAcceptable)
        {
          IsServerCertAcceptable = m_serverCertAcceptable(get(hServerCertContext),m_serverCertTrusted,m_serverCertNameMatches);
        }
        if(!IsServerCertAcceptable)
        {
          return SEC_E_UNKNOWN_CREDENTIALS;
        }
      }

      if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
      {
  			cbData = PlainSocket::SendMsg(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
			    DWORD err = GetLastError();
          if(err = WSAECONNRESET)
          {
            LogError("**** Server closed the connection unexpectedly");
          }
          else
          {
            LogError("**** Error %d sending data to server (2)",err);
          }
          g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
          m_context.Close();
          return SEC_E_INTERNAL_ERROR;
        }

        DebugMsg("%d bytes of handshake data sent", cbData);
        PrintHexDump(cbData, OutBuffers[0].pvBuffer);
        DebugMsg("\n");

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = nullptr;
      }
    }


    //
    // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
    // then we need to read more data from the server and try again.
    //

    if(scRet == SEC_E_INCOMPLETE_MESSAGE)
    {
      continue;
    }

    //
    // If InitializeSecurityContext returned SEC_E_OK, then the 
    // handshake completed successfully.
    //

    if (scRet == SEC_E_OK)
    {
      //
      // If the "extra" buffer contains data, this is encrypted application
      // protocol layer stuff. It needs to be saved. The application layer
      // will later decrypt it with DecryptMessage.
      //

      DebugMsg("Handshake was successful");

      if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
      {
			  MoveMemory(m_readBuffer,
                   m_readBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                   InBuffers[1].cbBuffer);

				m_readBufferBytes = InBuffers[1].cbBuffer;

        DebugMsg("%d bytes of app data was bundled with handshake data", m_readBufferBytes);
      }
      else
      {
        m_readBufferBytes = 0;
      }

      //
      // Bail out to quit
      //

      break;
    }

    //
    // Check for fatal error.
    //
    if(FAILED(scRet))
    {
      LogError("**** Error %#x returned by InitializeSecurityContext (2)",scRet);
      break;
    }

    //
    // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
    // then the server just requested client authentication. 
    //
    if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
    {
      //
      // The server has requested client authentication and
      // the credential we supplied didn't contain an acceptable 
			// client certificate.
      //

      // 
      // This function will read the list of trusted certificate
      // authorities ("issuers") that was received from the server
      // and attempt to find a suitable client certificate that
      // was issued by one of these. If this function is successful, 
      // then we will connect using the new certificate. Otherwise,
      // we will attempt to connect anonymously (using our current
      // credentials).
      //

      // 
      // Note the a server will NOT send an issuer list if it has the registry key
      // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
      // has a DWORD value called SendTrustedIssuerList set to 0
      //

	    scRet = GetNewClientCredentials();

      // Go around again.
      if (scRet == SEC_E_OK)
      {
        fDoRead = FALSE;
        scRet = SEC_I_CONTINUE_NEEDED;
        continue;
      }
      else
      {
        LogError("**** Error %08x returned by GetNewClientCredentials", scRet);
        break;
      }
    }

    //
    // Copy any leftover data from the "extra" buffer, and go around
    // again.
    //

    if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
    {
      MoveMemory(m_readBuffer,
                 m_readBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                 InBuffers[1].cbBuffer);

      cbIoBuffer = InBuffers[1].cbBuffer;
    }
    else
    {
      cbIoBuffer = 0;
    }
  }

  // Delete the security context in the case of a fatal error.
  if(FAILED(scRet))
  {
    m_context.Close();
  }
  return scRet;
}

bool 
SecureClientSocket::Close()
{
  return Disconnect() == 0;
}

int 
SecureClientSocket::Disconnect(int p_side /*= SD_BOTH*/)
{
  // In plain mode, do the PlainSocket disconnect
  if(InSecureMode() == false)
  {
    return PlainSocket::Disconnect(p_side);
  }

  // prepare for secure disconnect
  DWORD           dwType;
  PBYTE           pbMessage;
  DWORD           cbMessage;
  DWORD           cbData;

  SecBufferDesc   OutBuffer;
  SecBuffer       OutBuffers[1];
  DWORD           dwSSPIFlags;
  DWORD           Status;

  //
  // Notify SCHANNEL that we are about to close the connection.
  //

  dwType = SCHANNEL_SHUTDOWN;

  OutBuffers[0].pvBuffer   = &dwType;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = sizeof(dwType);

  OutBuffer.cBuffers  = 1;
  OutBuffer.pBuffers  = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  Status = g_pSSPI->ApplyControlToken(&get(m_context), &OutBuffer);

  if(FAILED(Status)) 
  {
    LogError("**** Error 0x%x returned by ApplyControlToken", Status);
    return Status;
  }

  //
  // Build an SSL close notify message.
  //

  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                ISC_REQ_REPLAY_DETECT     |
                ISC_REQ_CONFIDENTIALITY   |
                ISC_RET_EXTENDED_ERROR    |
                ISC_REQ_ALLOCATE_MEMORY   |
                ISC_REQ_STREAM;

  OutBuffers[0].pvBuffer   = NULL;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = 0;

  OutBuffer.cBuffers  = 1;
  OutBuffer.pBuffers  = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
  cbMessage = OutBuffers[0].cbBuffer;


  //
  // Send the close notify message to the server.
  //

  if(pbMessage != NULL && cbMessage != 0)
  {
		cbData = PlainSocket::SendPartial(pbMessage, cbMessage);
    if(cbData == SOCKET_ERROR || cbData == 0)
    {
      Status = WSAGetLastError();
      LogError("**** Error %d sending close notify", Status);
      return Status;
    }

    DebugMsg("Sending Close Notify");
    DebugMsg("%d bytes of handshake data sent", cbData);
    PrintHexDump(cbData, pbMessage);
    DebugMsg("\n");

    // Free output buffer.
    g_pSSPI->FreeContextBuffer(pbMessage);
  }

  return Status;
}

bool 
SecureClientSocket::GetServerCertNameMatches()
{
	return m_serverCertNameMatches;
}

bool 
SecureClientSocket::GetServerCertTrusted()
{
	return m_serverCertTrusted;
}

SECURITY_STATUS 
SecureClientSocket::GetNewClientCredentials()
{
  CredentialHandle hCreds;
  SecPkgContext_IssuerListInfoEx IssuerListInfo;
  SECURITY_STATUS Status;

  //
  // Read list of trusted issuers from schannel.
  // 
  // Note the a server will NOT send an issuer list if it has the registry key
  // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
  // has a DWORD value called SendTrustedIssuerList set to 0
  //

  Status = g_pSSPI->QueryContextAttributes(&get(m_context),
                                  SECPKG_ATTR_ISSUER_LIST_EX,
                                  (PVOID)&IssuerListInfo);
  if(Status != SEC_E_OK)
  {
    LogError("Error 0x%08x querying issuer list info", Status);
    return Status;
  }

  DebugMsg("Issuer list information returned, issuers = %d", IssuerListInfo.cIssuers);

  // Now go ask for the client credentials
  PCCERT_CONTEXT pCertContext = NULL;
  ConstCertContextHandle hCertContext;

  if(m_selectClientCertificate)
  {
    Status = m_selectClientCertificate(pCertContext,&IssuerListInfo,true);
  }
  if(FAILED(Status))
  {
    LogError("Error 0x%08x selecting client certificate", Status);
    return Status;
  }
  attach(hCertContext, pCertContext);
  if(!hCertContext)
  {
    LogError("No suitable client certificate is available to return to the server");
  }
  Status = CreateCredentialsFromCertificate(set(hCreds), get(hCertContext));

  if (SUCCEEDED(Status) && hCreds)
  {
    // Store the new ones
    m_clientCredentials = std::move(hCreds);
  }
  return Status;

  //
  // Many applications maintain a global credential handle that's
  // anonymous (that is, it doesn't contain a client certificate),
  // which is used to connect to all servers. If a particular server
  // should require client authentication, then a new credential 
  // is created for use when connecting to that server. The global
  // anonymous credential is retained for future connections to
  // other servers.
  //
  // Maintaining a single anonymous credential that's used whenever
  // possible is most efficient, since creating new credentials all
  // the time is rather expensive.
  //
}

SECURITY_STATUS 
SecureClientSocket::CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
{
  // Build SCHANNEL credential structure.
  SCHANNEL_CRED   SchannelCred = { 0 };
  SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
  if (pCertContext)
  {
    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext;
  }
  SchannelCred.grbitEnabledProtocols = m_sslClass; // SP_PROT_TLS1_2_CLIENT;
  SchannelCred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

  SECURITY_STATUS Status;
  TimeStamp       tsExpiry;
  // Get a handle to the SSPI credential
  Status = g_pSSPI->AcquireCredentialsHandle(
            NULL,                   // Name of principal
            UNISP_NAME,             // Name of package
            SECPKG_CRED_OUTBOUND,   // Flags indicating use
            NULL,                   // Pointer to logon ID
            &SchannelCred,          // Package specific data
            NULL,                   // Pointer to GetKey() func
            NULL,                   // Value to pass to GetKey()
            phCreds,                // (out) Credential Handle
            &tsExpiry);             // (out) Lifetime (optional)

  if (Status != SEC_E_OK)
  {
    DWORD dw = ::GetLastError();
    if(Status == SEC_E_UNKNOWN_CREDENTIALS)
    {
      LogError("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. LastError=%d",dw);
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
SecureClientSocket::SendMsg(LPCVOID p_buffer,const ULONG p_length)
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
    // Calculate max block to send. Must NOT be larger than MaxMsgSize (4 * 4K BLOCKSIZE)
    ULONG toSend = p_length - total_bytes_sent;
    if(toSend > MaxMsgSize)
    {
      toSend = MaxMsgSize;
    }

    bytes_sent = SecureClientSocket::SendPartial((char*)p_buffer + total_bytes_sent,toSend);
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
SecureClientSocket::RecvMsg(LPVOID p_buffer,const ULONG p_length)
{
  ULONG bytes_received = 0;
  ULONG total_bytes_received = 0;

  while(total_bytes_received < p_length)
  {
    bytes_received = SecureClientSocket::RecvPartial((char*)p_buffer + total_bytes_received,p_length - total_bytes_received);
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
