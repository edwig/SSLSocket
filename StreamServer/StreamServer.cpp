/////////////////////////////////////////////////////////////////////////////
// 
// StreamServer test client
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "Listener.h"
#include "SocketStream.h"
#include "SSLUtilities.h"
#include "Logging.h"
#include <memory>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

CString g_header  ("220 SSLSOCKET StreamServer ready\r\n");
CString g_okstring("220 OK\r\n");
CString g_closing ("221 Closing transmission channel\r\n");


CString GetCertName(PCCERT_CONTEXT pCertContext)
{
   CString certName;
   auto good = CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, certName.GetBuffer(128), certName.GetAllocLength()-1);
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

SECURITY_STATUS 
SelectServerCert(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)
{
  // Add "true" to look in user store, "false", or nothing looks in machine store
   SECURITY_STATUS status = CertFindServerByName(pCertContext, pszSubjectName,false); 
   if(pCertContext)
   {
     wcout << "Server certificate requested for " << pszSubjectName << ", found \"" << GetCertName(pCertContext) << "\"" << endl;
   }
   return status;
}

bool 
ClientCertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted)
{
  if(trusted)
  {
    cout << "A trusted";
  }
  else
  {
    cout << "An untrusted";
  }
  wcout << " client certificate was returned for \"" << GetCertName(pCertContext) << "\"" << endl;
  
  // Meaning any certificate is fine, trusted or not, but there must be one
  return NULL != pCertContext; 
}

// Keep the original test program around, in case we screw up
// and need to go back to a 'last known' good...
void 
OriginalTestProgram(SocketStream* p_serverSocket)
{
  // Start SSL for the server
  p_serverSocket->InitializeSSL();

  // This is the code to be executed each time a socket is opened
  char MsgText[100];

  cout << "A connection has been made, worker started, sending hello" << endl;
  p_serverSocket->SendPartial("Hello from server",17);
  int len = p_serverSocket->RecvPartial(MsgText,sizeof(MsgText) - 1);
  if(len > 0)
  {
    MsgText[len] = '\0'; // Terminate the string, for convenience
    cout << "Received " << MsgText << endl;
    cout << "Sending goodbye from server" << endl;
    p_serverSocket->SendPartial("Goodbye from server",19);
  }
  else
  {
    cout << "No response data received " << endl;
  }
  cout << "Exiting worker" << endl << endl;
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
  char buffer[1024];
  bool result = false;

  p_string.Empty();
  int len = p_socket->RecvPartial(buffer,1024);
  if(len > 0)
  {
    result   = true;
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

void
NewTestProgram(SocketStream* p_socket)
{
  cout << "Sending our server header..." << endl;
  SendingString(p_socket,g_header);

  CString data;
  while(ReceiveString(p_socket,data))
  {
    CString word = ExtractWord(data);

    // See if we must stop the receiving loop
    if(word.CompareNoCase("quit") == 0)
    {
      SendingString(p_socket,g_closing);
      break;
    }
    
    // See if we must switch
    if(word.CompareNoCase("starttls") == 0)
    {
      // Send the OK, Go ahead confirmation
      SendingString(p_socket,g_okstring);

      // Start SSL for the server
      if(FAILED(p_socket->InitializeSSL()))
      {
        cout << "Failed to engage SSL/TLS mode..." << endl;
        return;
      }
      continue;
    }

    // Accept the command for now
    SendingString(p_socket,g_okstring);
  }
  cout << "Exiting worker..." << endl << endl;
}

int main(int argc,char* argv[],char* envp[])
{
  if(!IsUserAdmin())
  {
    cout << "WARNING: The server is not running as an administrator." << endl;
    getchar();
    exit(3);
  }
	const int portNumber = 41000;
	
  SetSocketLogging(SOCK_LOGGING_FULLTRACE);

  // The one and only listener
  unique_ptr<Listener> listener(new Listener());

  // Set reasonable timeouts
  listener->SetSendTimeoutSeconds(30);
  listener->SetRecvTimeoutSeconds(60);

  // Connect function where we can select our server certificate
  listener->m_selectServerCert     = SelectServerCert;
  // Filling in this function call will request a client certificate
  // Leaving it out will run an SSL/TLS connection without one
  listener->m_clientCertAcceptable = ClientCertAcceptable;

	listener->Initialize(portNumber);

  cout << "Starting to listen on port: " << portNumber << endl;
  listener->BeginListening([](SocketStream* p_serverSocket)
  {
    // OriginalTestProgram(p_serverSocket);
    NewTestProgram(p_serverSocket);
	});

	cout << "Listening, press any key to exit.\n" << endl;
	getchar();
	listener->EndListening();

  WSACleanup();
	return 0;
}
