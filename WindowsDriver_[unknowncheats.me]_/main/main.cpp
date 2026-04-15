#include "start/point.h"

inline bool admin = true;

typedef struct _SWAP {
UNICODE_STRING Name;
PVOID* Swap;
PDRIVER_DISPATCH Original;
} SWAP, * PSWAP;

static struct _SWAPS {
SWAP Buffer[0xFF];
ULONG Length;
};

_SWAPS SWAPS = { 0 };

NTSTATUS AppendSwap(UNICODE_STRING name, PDRIVER_DISPATCH* swap, NTSTATUS(*hook)(PDEVICE_OBJECT device, PIRP irp), PDRIVER_DISPATCH* original) {

PSWAP entry = &SWAPS.Buffer[SWAPS.Length++];

entry->Swap = (PVOID*)swap;
entry->Original = (PDRIVER_DISPATCH)InterlockedExchangePointer(entry->Swap, hook);
entry->Name = name;

*original = entry->Original;

return STATUS_SUCCESS;
}

NTSTATUS SwapControl(UNICODE_STRING driver, NTSTATUS(*hook)(PDEVICE_OBJECT device, PIRP irp), PDRIVER_DISPATCH* original) {
UNICODE_STRING str = driver;
PDRIVER_OBJECT object = 0;
NTSTATUS _status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&object);
if (NT_SUCCESS(_status)) {
AppendSwap(str, &object->MajorFunction[IRP_MJ_DEVICE_CONTROL], hook, original);
ObDereferenceObject(object);
}
else {
return STATUS_UNSUCCESSFUL;
}

return STATUS_SUCCESS;
}

NTSTATUS DriverEntry ( PDRIVER_OBJECT DriverObject , PUNICODE_STRING Driverregistry )
{
UNREFERENCED_PARAMETER ( DriverObject );
UNREFERENCED_PARAMETER ( Driverregistry );

if ( !admin ) {
startup.run_checks ( );
}

// Read HWID seed written by launcher to HKLM\SOFTWARE\SPOOFER\P
UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\SPOOFER");
kmdf_settings::hwid_seed = (ULONG)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"P"));
DbgPrintEx(0, 0, "[WD] Seed: %u\n", kmdf_settings::hwid_seed);
srand(kmdf_settings::hwid_seed);

// disk.spoof: hooks disk driver internals — disabled until kernel offsets verified for 26100
//__try { disk.spoof(); }
//__except (EXCEPTION_EXECUTE_HANDLER) { DbgPrintEx(0, 0, "[WD] disk.spoof EXCEPTION 0x%X\n", GetExceptionCode()); }

// motherboard.spoof: pattern-scans ntoskrnl for SMBIOS physical address, then maps it.
// Has version check for 26100. Wrapped in SEH — if pattern not found it returns STATUS_UNSUCCESSFUL.
__try { motherboard.spoof(); }
__except (EXCEPTION_EXECUTE_HANDLER) {
DbgPrintEx(0, 0, "[WD] motherboard.spoof EXCEPTION 0x%X\n", GetExceptionCode());
}

// mac.spoof: reads NDIS kernel offsets from HKLM\SOFTWARE\SPOOFER\N1-N6.
// Launcher writes sentinel values so guard check "if (!offGlobalFilterList)" fires → safe return.
// Without sentinels: missing keys XOR to garbage address → KMODE_EXCEPTION_NOT_HANDLED.
__try { mac.spoof(); }
__except (EXCEPTION_EXECUTE_HANDLER) {
DbgPrintEx(0, 0, "[WD] mac.spoof EXCEPTION 0x%X\n", GetExceptionCode());
}

// ARP / TCP dispatch hooks: these are PERSISTENT kernel hooks called on every network IRP.
// They currently crash (bad NDIS struct offsets for Win11 26100) AFTER DriverEntry returns,
// so DriverEntry SEH cannot catch them. Disabled until hook functions are verified safe.
//
// __try { SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy"), NsiDispatchHook, &g_OriginalNsiDispatch); }
// __except (EXCEPTION_EXECUTE_HANDLER) { DbgPrintEx(0, 0, "[WD] SwapControl(nsiproxy) EXCEPTION 0x%X\n", GetExceptionCode()); }
//
// __try { SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsi"), NsiDispatchHook2, &g_OriginalNsiDispatch2); }
// __except (EXCEPTION_EXECUTE_HANDLER) { DbgPrintEx(0, 0, "[WD] SwapControl(nsi) EXCEPTION 0x%X\n", GetExceptionCode()); }
//
// __try { SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\Tcp"), TcpDispatchHook, &g_OriginalTcpDispatch); }
// __except (EXCEPTION_EXECUTE_HANDLER) { DbgPrintEx(0, 0, "[WD] SwapControl(Tcp) EXCEPTION 0x%X\n", GetExceptionCode()); }

DbgPrintEx(0, 0, "[WD] DriverEntry complete — spoofer active\n");
return STATUS_SUCCESS;
}