#ifndef  NT_API
#define NT_API 1 
#include  "Struct.h"



NTSTATUS
NTAPI
NtQueryInformationProcess
(
    IN HANDLE               ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID               ProcessInformation,
    IN ULONG                ProcessInformationLength,
    OUT PULONG              ReturnLength
);


NTSTATUS
NTAPI 
NtSetInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
);

NTSTATUS 
NTAPI 
NtQueryInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);


NTSTATUS 
NTAPI 
NtQueryObject
(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);


#endif