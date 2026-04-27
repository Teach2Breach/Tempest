/*
 * BM-T2005: Call Stack Spoofing — Demo
 *
 * Demonstrates:
 *   1. Stargate initialization (indirect syscalls)
 *   2. Stack spoofing initialization (gadget scanning + synthetic stack)
 *   3. Unspoofed syscall (Stargate only — unbacked frames)
 *   4. Spoofed syscall (Stargate + spoofed frames — all frames in legit modules)
 *
 * Both calls use NtQueryInformationProcess to retrieve the current PID.
 * The results should be identical — the difference is invisible to the user
 * but visible to any EDR walking the call stack.
 *
 * Build: make demo.exe  (or: make debug  for verbose gadget scanning output)
 * Platform: Windows x64 only
 */

#include <stdio.h>
#include <string.h>

#include "bm_spoof.h"
#include "stargate.h"
#include "loader.h"

/* FNV-1a hashes */
#define H_NTQUERYINFORMATIONPROCESS  0x23F41F6Eu

/* PROCESS_BASIC_INFORMATION — defined in winternl.h (included via stargate.h) */

int main(void) {
    printf("BM-T2005: Call Stack Spoofing\n\n");

    /* ---------------------------------------------------------------
     * Step 1: Initialize Stargate
     * --------------------------------------------------------------- */
    printf("[*] Initializing Stargate...\n");
    if (sg_init(NULL) != 0) {
        printf("[-] Stargate init failed\n");
        return 1;
    }
    printf("[+] Stargate initialized (mode=%s)\n",
           sg_get_syscall_mode() == SG_INDIRECT ? "indirect" : "direct");

    /* ---------------------------------------------------------------
     * Step 2: Initialize stack spoofing
     * --------------------------------------------------------------- */
    printf("[*] Initializing call stack spoofing...\n");
    if (bm_spoof_init() != 0) {
        printf("[-] Stack spoofing init failed (gadgets not found)\n");
        sg_cleanup();
        return 1;
    }
    printf("[+] Call stack spoofing ACTIVE\n\n");

    /* Resolve NtQueryInformationProcess */
    SgSyscall sc_nqip;
    if (sg_resolve_hash(H_NTQUERYINFORMATIONPROCESS, &sc_nqip) != 0) {
        printf("[-] Failed to resolve NtQueryInformationProcess\n");
        bm_spoof_cleanup();
        sg_cleanup();
        return 1;
    }
    printf("[+] NtQueryInformationProcess: SSN=0x%04lX\n\n",
           (unsigned long)sc_nqip.ssn);

    /* ---------------------------------------------------------------
     * Test 1: Unspoofed (Stargate indirect only)
     * --------------------------------------------------------------- */
    printf("[*] Test 1: Unspoofed NtQueryInformationProcess (Stargate only)\n");
    {
        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG ret_len = 0;

        NTSTATUS st = sg_call_5(&sc_nqip,
            (void *)(LONG_PTR)-1,            /* CurrentProcess handle */
            (void *)(ULONG_PTR)0,            /* ProcessBasicInformation */
            &pbi,
            (void *)(ULONG_PTR)sizeof(pbi),
            &ret_len);

        printf("    NTSTATUS: 0x%08lX\n", (unsigned long)st);
        if (st == 0) {
            printf("    PID: %llu\n", (unsigned long long)pbi.UniqueProcessId);
            printf("    Parent PID: %llu\n",
                   (unsigned long long)pbi.InheritedFromUniqueProcessId);
        }
        printf("    (frame 1+ points to unbacked memory — detectable by EDR)\n\n");
    }

    /* ---------------------------------------------------------------
     * Test 2: Spoofed (Stargate + call stack spoofing)
     * --------------------------------------------------------------- */
    printf("[*] Test 2: Spoofed NtQueryInformationProcess (Stargate + spoofing)\n");
    {
        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG ret_len = 0;

        NTSTATUS st = bm_spoof_call_5(&sc_nqip,
            (void *)(LONG_PTR)-1,            /* CurrentProcess handle */
            (void *)(ULONG_PTR)0,            /* ProcessBasicInformation */
            &pbi,
            (void *)(ULONG_PTR)sizeof(pbi),
            &ret_len);

        printf("    NTSTATUS: 0x%08lX\n", (unsigned long)st);
        if (st == 0) {
            printf("    PID: %llu\n", (unsigned long long)pbi.UniqueProcessId);
            printf("    Parent PID: %llu\n",
                   (unsigned long long)pbi.InheritedFromUniqueProcessId);
        }
        printf("    (all frames in ntdll/kernelbase/kernel32 — EDR sees clean stack)\n\n");
    }

    /* ---------------------------------------------------------------
     * Cleanup
     * --------------------------------------------------------------- */
    printf("[*] Cleaning up...\n");
    bm_spoof_cleanup();
    sg_cleanup();
    printf("[+] Done\n");

    return 0;
}
