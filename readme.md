# SSLSocket

The SSLSocket library has various MS-Windows sockets for standard and secure (HTTPS) use.
The main components are:
 
 - PlainSocket: For standard two-way sockets
 - SecureClientSocket: A client socket that handles client certificates
 - SecureServerSocket: A server socket that sets up the server SSL/TLS certificate

All three types of sockets are derived from "SocketStream", a generic virtual main class.
Besides the sockets, the library also contains functions for handeling SSL/TLS certificates, encryption, a server incoming connections listener and various system functions for handeling the certificates in the MS-Windows certificate store.

One of the important characteristics of the library is that a non-secure connection can upgrade halfway the process to a secure connection. This is needed for e.g. a SMTP connection where the 'STARTTLS' command must be able to upgrade the connection for insecure to secure.
