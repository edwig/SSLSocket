/////////////////////////////////////////////////////////////////////////////
// 
// StreamClient test program
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "PlainSocket.h"
#include "SecureClientSocket.h"
#include "EventWrapper.h"
#include <atlconv.h>
#include <string>
#include <iostream>
#include <iomanip>
#include "SSLUtilities.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

// defined in another source file (CreateCertificate.cpp)
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCSTR Subject = NULL, LPCSTR FriendlyName = NULL, LPCSTR Description = NULL);

// Given a pointer to a certificate context, return the certificate name 
// (the friendly name if there is one, the subject name otherwise).
//
CString GetCertName(PCCERT_CONTEXT pCertContext)
{
   CString certName;
   auto good = CertGetNameString(pCertContext
                                ,CERT_NAME_FRIENDLY_DISPLAY_TYPE
                                ,0
                                ,NULL
                                ,certName.GetBuffer(128)
                                ,certName.GetAllocLength() - 1);
   certName.ReleaseBuffer();
   if(good)
   {
     return certName;
   }
   else
   {
     return "<unknown>";
   }
}

// Function to evaluate the certificate returned from the server
// if you want to keep it around call CertDuplicateCertificateContext, then CertFreeCertificateContext to free it
bool CertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)
{
  if(trusted)
  {
    cout << "A trusted";
  }
  else
  {
    cout << "An untrusted";
  }
  wcout << " server certificate was returned with a name ";
  if(matchingName)
  {
    cout << "match";
  }
  else
  {
    cout << "mismatch";
  }
  // wcout for WCHAR* handling
  wcout << " called \"" << GetCertName(pCertContext) << "\"" << endl; 
  if(false && SSL_socket_logging && pCertContext)
  {
    ShowCertInfo(pCertContext,"Client Received Server Certificate");
  }
  return true; // Any certificate will do
}

// This will get called once, or twice, the first call with "Required" false, which can return any
// certificate it likes, or none at all. If it returns one, that will be sent to the server.
// If that call did not return an acceptable certificate, the procedure may be called again if the server requests a 
// client certificate, whatever is returned on the first call (including null) is sent to the server which gets to decide
// whether or not it is acceptable. If there is a second call (which will have "Required" true and may have 
// pIssuerListInfo non-NULL) it MUST return a certificate or the handshake will fail.

SECURITY_STATUS SelectClientCertificate(PCCERT_CONTEXT& pCertContext, SecPkgContext_IssuerListInfoEx* pIssuerListInfo, bool Required)
{
  SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;

  if (Required)
  {
    // A client certificate must be returned or the handshake will fail
    if(pIssuerListInfo && pIssuerListInfo->cIssuers == 0)
    {
      cout << "Client certificate required, issuer list is empty";
    }
    else
    {
      cout << "Client certificate required, issuer list provided";
      Status = CertFindFromIssuerList(pCertContext, *pIssuerListInfo);
      if(!pCertContext)
      {
        cout << " but no certificates matched";
      }
    }
    if(!pCertContext)
    {
      // Select any valid certificate, regardless of issuer
      Status = CertFindClient(pCertContext); 
    }
    // If a search for a required client certificate failed, just make one
    if (!pCertContext)
    {
      cout << ", none found, creating one";
      pCertContext = CreateCertificate(false, GetUserName() + " at " + GetHostName());
      if(pCertContext)
      {
        Status = S_OK;
      }
      else
      {
        DWORD LastError = GetLastError();
        cout << endl << "**** Error 0x" << std::hex << std::setw(8) << std::setfill('0') << LastError << " in CreateCertificate" << endl 
             << "Client certificate";
        Status = HRESULT_FROM_WIN32(LastError);
      }
    }
  }
  else
  {
    cout << "Optional client certificate requested (without issuer list)";
    // Enable the next line to preemptively guess at an appropriate certificate 
    if(false && FAILED(Status))
    {
      Status = CertFindClient(pCertContext); // Select any valid certificate
    }
  }
  if(pCertContext)
  {
    cout << ", selected name: " << GetCertName(pCertContext) << endl; // wcout for WCHAR* handling
  }
  else
  {
    cout << ", no certificate found." << endl;
  }
  if(false && SSL_socket_logging && pCertContext)
  {
    ShowCertInfo(pCertContext,"Client certificate being returned");
  }
  return Status;
}

// Keep the original test program around, in case we screw up
// and need to go back to a 'last known' good...
void 
OriginalTestProgram(SecureClientSocket* p_socket)
{
  cout << "Socket connected to server, initializing SSL" << endl;
  char Msg[100];

  HRESULT hr = p_socket->InitializeSSL();
  if(SUCCEEDED(hr))
  {
    cout << "Connected, cert name matches=" << p_socket->GetServerCertNameMatches()
         << ", cert is trusted=" << p_socket->GetServerCertTrusted() << endl << endl;

    cout << "Sending greeting" << endl;
    if(p_socket->SendPartial("Hello from client",17) != 17)
    {
      cout << "Wrong number of characters sent" << endl;
    }

    cout << "Listening for messages from server" << endl;
    int len = 0;
    while(0 < (len = p_socket->RecvPartial(Msg,sizeof(Msg))))
    {
      cout << "Received " << CString(Msg,len) << endl;
    }
    p_socket->Close();
  }
  else
  {
    cout << "SSL client initialize failed" << endl;
  }
}

void SendingString(SocketStream* p_socket,CString p_string)
{
  static int line = 0;

  if(p_socket->SendMsg(p_string.GetString(),p_string.GetLength()) != p_string.GetLength())
  {
    cout << "!! ERROR Sending string" << endl;
  }
  ++line;
  cout << "OUT : " << p_string;
}

bool ReceiveString(SocketStream* p_socket,CString& p_string)
{
  char buffer[1024 + 1];
  bool result = false;

  p_string.Empty();
  int len = p_socket->RecvPartial(buffer,1024);
  if(len > 0)
  {
    result = true;
    buffer[len] = 0;
    p_string = buffer;
    cout << "IN  : " << p_string;;
  }
  else
  {
    cout << "No response data received" << endl;
  }
  return result;
}

CString ExtractWord(CString& p_line)
{
  p_line = p_line.TrimRight("\r\n");

  int pos = p_line.Find(' ');
  if(pos > 0 && pos < p_line.GetLength())
  {
    CString word = p_line.Left(pos);
    p_line = p_line.Mid(pos + 1);
    return word;
  }
  CString word(p_line);
  p_line.Empty();
  return word;
}

void StartSSL(SecureClientSocket* p_socket)
{
  HRESULT hr = p_socket->InitializeSSL();
  if(SUCCEEDED(hr))
  {
    cout << "Client switched to secure TLS mode" << endl;
  }
  else
  {
    cout << "SSL client initialize failed" << endl;
  }
}

void
NewTestProgram(SecureClientSocket* p_socket)
{
  cout << "Socket connected to server..." << endl;

  CString data;
  int command = 0;
  while(ReceiveString(p_socket,data))
  {
    // Show what the server did send us
    cout << data;

    CString code = ExtractWord(data);

    // Last command was STARTTLS and servers said "OK"
    if(command == 2 && atoi(code) == 220)
    {
      StartSSL(p_socket);
    }

    if(atoi(code) == 221)
    {
      cout << "Server detached channel" << endl;
      return;
    }

    switch(++command)
    {
      case  1: SendingString(p_socket,"EHLO mail\r\n");break;
      case  2: SendingString(p_socket,"STARTTLS\r\n"); break;
      case  3: SendingString(p_socket,"TO\r\n");       break;
      case  4: SendingString(p_socket,"SUBJECT\r\n");  break;
      case  5: SendingString(p_socket,"QUIT\r\n");     break;
      default: break;
    }
  }
}

// StreamClient [hostname [portnumber]]
// Works default on port 41000 on the same system
//
// SMTP Ports:
// 25    -> Insecure SMTP email
// 465   -> No longer in use!!
// 587   -> SSL/TLS connected SMTP + Authenticated email
//
int main(int argc,char* argv[])
{
  // Defaults
  CString hostName(GetHostName(ComputerNameDnsFullyQualified));
  int     port = 41000;

  // Get overrides from the command line
  if(argc >= 2)
  {
    hostName.SetString(argv[1]);
    if(argc >= 3)
    {
      port = atoi(argv[2]);
    }
  }

  // Use full tracing on the default debug pane
  SetSocketLogging(SOCK_LOGGING_FULLTRACE);

  // Create a new client socket
	EventWrapper ShutDownEvent;
  SecureClientSocket* socket = new SecureClientSocket(ShutDownEvent);

  // Settings for a client socket
  socket->SetConnTimeoutSeconds(15);
  socket->SetRecvTimeoutSeconds(30);
	socket->SetSendTimeoutSeconds(60);
  socket->SetKeepaliveTime(10);
  socket->SetKeepaliveInterval(10);
  socket->SetUseKeepAlive(true);
  socket->SetSSLProtectionLevel(TLS_12);
  socket->m_serverCertAcceptable    = CertAcceptable;
  socket->m_selectClientCertificate = SelectClientCertificate;

  socket->Initialize();

	wcout << "Connecting to " << hostName.GetString() << ":" << port << endl;
	bool connected = socket->Connect(hostName, port);
	if (connected)
	{
    //OriginalTestProgram(socket);
    NewTestProgram(socket);

    // Break listening side
		::SetEvent(ShutDownEvent);
    // Close both sides of the socket
    socket->Close();
  }
	else
	{
		cout << "Socket failed to connect to server" << endl;
	}
	cout << "Press any key to exit" << endl;

  WSACleanup();

  delete socket;

	getchar();
	return 0;
}

