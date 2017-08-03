/////////////////////////////////////////////////////////////////////////////
// 
// EventWrapper
//
// Original idea:
// David Maw: https://www.codeproject.com/Articles/1000189/A-Working-TCP-Client-and-Server-With-SSL
// License:   https://www.codeproject.com/info/cpol10.aspx
//
#pragma once
#include <synchapi.h>
#include <handleapi.h>

class EventWrapper
{
public:

	EventWrapper(LPSECURITY_ATTRIBUTES  p_eventAttributes = nullptr,
 				       BOOL                   p_manualReset     = TRUE,
					     BOOL                   p_initialState    = FALSE,
					     LPCTSTR                p_name            = nullptr)
	:m_event(nullptr)
	{	
	  m_event = ::CreateEvent(p_eventAttributes,p_manualReset,p_initialState,p_name);
    if(!m_event)
    {
      throw "No event created";
    }
	}

	HANDLE Event() const
	{
		return m_event;
	}

	operator const HANDLE()
	{
		return m_event;
	}

	~EventWrapper()
	{
		if(m_event)	
		{
			::CloseHandle(m_event);
			m_event = NULL;
		}
	}

private:
	HANDLE m_event;
};

