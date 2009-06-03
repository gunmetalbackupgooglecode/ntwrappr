#pragma once

#ifdef __cplusplus
extern "C" {
#endif

HANDLE
NTAPI
CreateDirectory(
	PWSTR Path
	);

HANDLE
NTAPI
CreateSymbolicLink(
	PWSTR Name,
	PWSTR Target
	);

HANDLE
NTAPI
CreateEvent(
    ULONG AccessMask,
    PWSTR wEventName OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
    );

HANDLE
NTAPI
OpenEvent(
    ULONG AccessMask,
    PWSTR Name
    );

#define EVENT_STATE_ERROR   ((ULONG)-1)

ULONG
NTAPI
SetEvent(
    HANDLE hEvent
    );


#ifdef __cplusplus
}
#endif
