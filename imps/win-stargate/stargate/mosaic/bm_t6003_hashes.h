/*
 * Vendored for Tempest (imps/win-stargate). Upstream: techniques/BM-T6003.
 * FNV-1a hashes for runtime EAT resolution (same as BM-T1001 loader.c).
 * Numeric constants only — names are matched at runtime (no plaintext).
 */

#ifndef BM_T6003_HASHES_H
#define BM_T6003_HASHES_H

#define H_BASE_KERNEL32_DLL           0xA25682A7u
#define H_BASE_NTDLL_DLL             0x1617909Fu

#define H_CloseHandle                0x7205C1B9u
#define H_WaitForSingleObjectEx       0x02A53ADDu
#define H_CreateEventW               0x93ED44BCu
#define H_NtWaitForSingleObject       0x44DBF482u
#define H_RtlAllocateHeap            0xF8765144u
#define H_RtlFreeHeap                0x2C30F5D1u

/* Mosaic v2 — timer queue lane + keyed-event lane */
#define H_CreateTimerQueue            0x3E48F8B1u
#define H_DeleteTimerQueue              0x6A541FB6u
#define H_CreateTimerQueueTimer         0x5C06DFCEu
#define H_DeleteTimerQueueTimer         0xE7F04727u
#define H_SetEvent                      0xECCEAB6Du
#define H_ResetEvent                   0xF1B71E8Cu

#define H_NtCreateKeyedEvent            0x9375B759u
#define H_NtWaitForKeyedEvent           0x18CEDC4Bu
#define H_NtReleaseKeyedEvent           0x17AB6B0Au

#define H_OutputDebugStringA              0x0B598A79u

#define H_NtTerminateThread               0x6FA5AC52u
#define H_GetCurrentThread                0xE8D337DCu

#endif /* BM_T6003_HASHES_H */
