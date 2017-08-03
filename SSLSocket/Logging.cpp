/////////////////////////////////////////////////////////////////////////////
// 
// Utilities for the SSL Socket library
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#include "stdafx.h"
#include "Logging.h"
#include <strsafe.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const int bufferLength = 1024;

// Current logging level
int SSL_socket_logging = SOCK_LOGGING_OFF;
// Current used printing function
OutputString printing = OutputDebugString;

void SetSocketLogging(int p_logging)
{
  if(p_logging >= SOCK_LOGGING_OFF && p_logging <= SOCK_LOGGING_FULLTRACE)
  {
    SSL_socket_logging = p_logging;
  }
}

void LogError(const char* p_format,...)
{
  char buf[bufferLength];
  StringCchPrintf(buf,sizeof(buf) / sizeof(char),"(%lu) : ERROR : ",GetCurrentThreadId());

  va_list arglist;
  va_start(arglist,p_format);
  StringCchVPrintf(&buf[strlen(buf)],sizeof(buf) / sizeof(char),p_format,arglist);
  va_end(arglist);

  StringCchCat(buf,sizeof(buf) / sizeof(char),"\n");
  (*printing)(buf);
}


void DebugMsg(const char* p_format, ...)
{
  if(SSL_socket_logging)
  {
    char buf[bufferLength];
    StringCchPrintf(buf, sizeof(buf)/sizeof(char), "(%lu) : ", GetCurrentThreadId());

    va_list arglist;
	  va_start(arglist, p_format);
	  StringCchVPrintf(&buf[strlen(buf)], sizeof(buf)/sizeof(char), p_format, arglist);
	  va_end(arglist);
    
    StringCchCat(buf, sizeof(buf)/sizeof(char), "\n");
	  (*printing)(buf);
  }
}

static void PrintHexDumpActual(DWORD p_length,const void* p_buffer)
{
  DWORD count = 0;
	CHAR  digits[] = "0123456789abcdef";
	CHAR  line[100];
	int   pos = 0;
	const byte* buffer = static_cast<const byte *>(p_buffer);

  // Only print the 'full' message at the highest level
  // otherwise, just print the first line
  if((SSL_socket_logging < SOCK_LOGGING_FULLTRACE) && (p_length > 16))
  {
    p_length = 16;
  }

	for(int index = 0; p_length; p_length -= count, buffer += count, index += count) 
	{
    DWORD i = 0;
		count = (p_length > 16) ? 16:p_length;

		sprintf_s(line, sizeof(line), "%4.4x  ", index);
		pos = 6;

		for(i = 0; i < count;i++) 
		{
			line[pos++] = digits[buffer[i] >> 4];
			line[pos++] = digits[buffer[i] & 0x0f];
			if(i == 7) 
			{
				line[pos++] = ':';
			} 
			else 
			{
				line[pos++] = ' ';
			}
		}
		for(; i < 16; i++) 
		{
			line[pos++] = ' ';
			line[pos++] = ' ';
			line[pos++] = ' ';
		}

		line[pos++] = ' ';

		for(i = 0; i < count; i++) 
		{
      if(buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%')
      {
        line[pos++] = '.';
      }
      else
      {
        line[pos++] = buffer[i];
      }
		}
		line[pos++] = 0;
		DebugMsg(line);
	}
}

void PrintHexDump(DWORD p_length, const void* p_buffer)
{
  if(SSL_socket_logging >= SOCK_LOGGING_TRACE)
  {
    PrintHexDumpActual(p_length,p_buffer);
  }
}
