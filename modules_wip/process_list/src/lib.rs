use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::ctypes::c_void as winapi_c_void;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPDWORD, MAX_PATH, ULONG};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
use winapi::shared::ntdef::{LPCWSTR, LPWSTR, PULONG, PVOID, STRING};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::TOKEN_USER;

use ntapi::ntldr::{LdrGetDllHandle, LdrGetProcedureAddress};
use ntapi::ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString};
use winapi::um::winnt::{
    TokenUser, ACCESS_MASK, MAXIMUM_ALLOWED, PSID, PSID_NAME_USE,
    TOKEN_INFORMATION_CLASS,
};

const STATUS_SUCCESS: NTSTATUS = 0;

#[macro_use]
extern crate litcrypt2;

use_litcrypt!("ageofmachine");

// Function to get a handle to a DLL module
fn ldr_get_dll(dll_name: &str) -> HMODULE {
    // Initialize a null pointer to a void type
    let mut handle: *mut winapi_c_void = std::ptr::null_mut();
    // Initialize a UNICODE_STRING structure
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the DLL name to a wide string (UTF-16)
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        // Initialize the UNICODE_STRING with the DLL name
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        // Get a handle to the DLL
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        // If the function fails or the handle is null, return null
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the handle to the DLL
    handle as HMODULE
}

// Function to get a function address from a DLL module
fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    // Initialize a null pointer to a void type
    let mut func: *mut winapi_c_void = std::ptr::null_mut();
    // Initialize an ANSI_STRING structure
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Initialize a UNICODE_STRING structure
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the function name to a wide string (UTF-16)
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        // Initialize the UNICODE_STRING with the function name
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        // Convert the UNICODE_STRING to an ANSI_STRING
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        // Get the address of the function
        let status = LdrGetProcedureAddress(
            dll as *mut winapi_c_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        // If the function fails or the function address is null, return null
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the function address
    func as FARPROC
}

pub fn get_process_list() -> String {
    //define a String to return our process list
    let mut process_list = String::new();

    //load ntdll using ldr_get_dll
    let ntdll = ldr_get_dll("ntdll.dll");
    let kernel32 = ldr_get_dll("kernel32.dll");

    let nt_get_next_process: NtGetNextProcess =
        unsafe { std::mem::transmute(ldr_get_fn(ntdll, &lc!("NtGetNextProcess"))) };
    //load GetProcessId using ldr_get_fn
    let get_process_id: GetProcessId =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("GetProcessId"))) };
    //load QueryFullProcessImageNameW using ldr_get_fn
    let query_full_process_image_name_w: QueryFullProcessImageNameW =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("QueryFullProcessImageNameW"))) };
    //load NtOpenProcessTokenEx using ldr_get_fn
    //load NtQueryInformationToken using ldr_get_fn
    let nt_open_process_token_ex: NtOpenProcessTokenEx =
        unsafe { std::mem::transmute(ldr_get_fn(ntdll, &lc!("NtOpenProcessTokenEx"))) };

    // Get the address of the LoadLibraryA function from kernel32.dll.
    let load_library_a: unsafe extern "system" fn(lpLibFileName: *const i8) -> HMODULE =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("LoadLibraryA"))) };

    // Get the address of the GetProcAddress function from kernel32.dll.
    let get_proc_address: unsafe extern "system" fn(
        hModule: HMODULE,
        lpProcName: *const i8,
    ) -> FARPROC = unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("GetProcAddress"))) };

    //define the function signature for NtGetNextProcess
    type NtGetNextProcess =
        unsafe extern "system" fn(HANDLE, ACCESS_MASK, u32, u32, *mut HANDLE) -> NTSTATUS;

    type GetProcessId = unsafe extern "system" fn(HANDLE) -> u32;

    type QueryFullProcessImageNameW =
        unsafe extern "system" fn(HANDLE, DWORD, *mut u16, *mut DWORD) -> BOOL;

    type NtOpenProcessTokenEx = unsafe extern "system" fn(
        //define the function signature for NtOpenProcessTokenEx
        HANDLE,
        ACCESS_MASK,
        ULONG,
        *mut HANDLE,
    ) -> NTSTATUS;

    // Get the address of the NtQueryInformationToken function from ntdll.dll.
    let get_token_information: unsafe extern "system" fn(
        HANDLE,
        TOKEN_INFORMATION_CLASS,
        PVOID,
        ULONG,
        PULONG,
    ) -> NTSTATUS =
        unsafe { std::mem::transmute(ldr_get_fn(ntdll, &lc!("NtQueryInformationToken"))) };

    // Load the advapi32.dll library.
    let advapi32 = unsafe { load_library_a("Advapi32.dll\0".as_ptr() as *const i8) };
    if advapi32.is_null() {
        return lc!("Failed to load advapi32.dll").into();
    }

    // Get the address of the LookupAccountSidW function from advapi32.dll.
    let lookup_account_sid_w_name = "LookupAccountSidW\0".as_ptr() as *const i8;
    let lookup_account_sid_w: unsafe extern "system" fn(
        LPCWSTR,
        PSID,
        LPWSTR,
        LPDWORD,
        LPWSTR,
        LPDWORD,
        PSID_NAME_USE,
    ) -> BOOL =
        unsafe { std::mem::transmute(get_proc_address(advapi32, lookup_account_sid_w_name)) };

        if lookup_account_sid_w as usize == 0 {
            return lc!("Failed to get LookupAccountSidW function pointer").into();
        }

    let mut h_process: HANDLE = 0 as _;

    while unsafe { nt_get_next_process(h_process, MAXIMUM_ALLOWED, 0, 0, &mut h_process) } == 0 {
        //println!("Process Handle: {:?}", h_process);

        // Get the process ID using GetProcessId
        let process_id = unsafe { get_process_id(h_process) };

        //print the process name and process id like process_name : process_id
        //println!("{}", process_id);

        //now call get_module_file_name_ex_w to get the process name
        let mut process_name: [u16; MAX_PATH] = [0; MAX_PATH];
        let mut process_name_length = MAX_PATH as DWORD;

        //if pid is 0, then don't call QueryFullProcessImageNameW,
        //as it will return error
        //otherwise call QueryFullProcessImageNameW

        if process_id != 0 {
            let result = unsafe {
                query_full_process_image_name_w(
                    h_process,
                    0,
                    process_name.as_mut_ptr(),
                    &mut process_name_length,
                ) as u32 //cast to u32
            };

            if result != 0 {
                // The function succeeded, add the process name and PID to process_list
                let process_name_str =
                    String::from_utf16_lossy(&process_name[..process_name_length as usize]);
                let process_name = process_name_str.trim_matches(char::from(0));

                // Get just the executable name from the full path
                let file_name = std::path::Path::new(&process_name);
                //copnvert the file_name to a string
                let file_name = file_name.file_name().unwrap().to_str().unwrap();

                //use NtOpenProcessTokenEx to get tokens and NtQueryInformationToken to get user name

                // Open a handle to the access token
                let mut token: HANDLE = std::ptr::null_mut();
                let status =
                    unsafe { nt_open_process_token_ex(h_process, MAXIMUM_ALLOWED, 0, &mut token) };
                /*if status != 0x00000000 {
                    return "NtOpenProcessToken failed".into();
                }*/
                //if NtOpenProcessTokenEx fails, go back to the beginning of the loop
                if status != 0x00000000 {
                    continue;
                }
                // Initialize the length of the return value to 0.
                let mut return_length = 0;

                // First call to GetTokenInformation to get the required buffer size.
                if unsafe {
                    get_token_information(
                        token,
                        TokenUser,
                        std::ptr::null_mut(),
                        0,
                        &mut return_length,
                    )
                } == 0
                {
                    return lc!("First GetTokenInformation failed.").into();
                }

                // Create a buffer of the required size.
                let mut token_user_buffer = vec![0u8; return_length as usize];

                // Second call to GetTokenInformation to get the TOKEN_USER.
                if unsafe { get_token_information(
                    token,
                    TokenUser,
                    token_user_buffer.as_mut_ptr() as *mut winapi_c_void,
                    return_length,
                    &mut return_length,
                )} != 0
                {
                    return lc!("Second GetTokenInformation failed.").into();
                }

                // Get the SID (Security Identifier) of the user associated with the token.
                let token_user = token_user_buffer.as_ptr() as *mut TOKEN_USER;
                let user_sid = unsafe { (*token_user).User.Sid };

                // Initialize buffers to hold the name and domain of the user.
                let mut name = [0u16; 256];
                let mut name_len = 256;
                let mut domain = [0u16; 256];
                let mut domain_len = 256;
                let mut sid_name_use = 0;

                // Call LookupAccountSidW to get the name and domain of the user.
                if unsafe {
                    lookup_account_sid_w(
                        std::ptr::null(),
                        user_sid as PSID,
                        name.as_mut_ptr(),
                        &mut name_len,
                        domain.as_mut_ptr(),
                        &mut domain_len,
                        &mut sid_name_use,
                    )
                } == 0
                {
                    return lc!("LookupAccountSidW failed").into();
                }

                // Convert the name from UTF-16 to a Rust String.
                let username = String::from_utf16_lossy(&name[..name_len as usize]);

                process_list.push_str(&format!("{} : {} : {}", username, process_id, file_name));
                process_list.push('\n');
            }
        }
    }

    // Close the process handle
    unsafe {
        CloseHandle(h_process);
    }

    //return the process_list
    process_list
}
