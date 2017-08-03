/////////////////////////////////////////////////////////////////////////////
// 
// SSL Socket Library
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once

// Logging level in the SSL socket library
//
#define SOCK_LOGGING_OFF       0    // No logging
#define SOCK_LOGGING_ON        1    // Results logging
#define SOCK_LOGGING_TRACE     2    // Hexdump tracing first line
#define SOCK_LOGGING_FULLTRACE 3    // Full hexdump tracing

extern int SSL_socket_logging;  // Holds the current logging level

// Definition of a 'real' printing function
typedef void(*OutputString)(LPCSTR lpOutputString);
// Holds the 'real' printing function, defaulting to "OutputDebugString"
extern OutputString printing;

// Functions

void LogError(const char* p_format,...);
void DebugMsg(const char* p_format,...);
void PrintHexDump(DWORD p_length,const void* p_buffer);
void SetSocketLogging(int p_logging);
