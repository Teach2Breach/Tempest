#![allow(unused_variables)]
#![allow(unused_assignments)]

use std::ffi::{CString, OsString};

pub fn get_external_ip(module_name: usize) -> String {
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
    let endpoint = CString::new("/").unwrap();
    let method = CString::new("GET").unwrap();

    // Define the function pointer type matching InternetOpenA's signature
    let internet_open: unsafe extern "system" fn(
        *const i8, // lpszAgent
        u32,       // dwAccessType
        *const i8, // lpszProxy
        *const i8, // lpszProxyBypass
        u32,       // dwFlags
    ) -> isize; // HINTERNET is pointer-sized

    let ret: Option<isize>;

    unsafe {
        // INTERNET_OPEN_TYPE_DIRECT = 1
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetOpenA",
            internet_open,
            ret,
            user_agent.as_ptr(),
            1u32,
            std::ptr::null(),
            std::ptr::null(),
            0u32
        );
    }

    let handle = match ret {
        Some(h) if h != 0 => h,
        _ => panic!("InternetOpenA failed"),
    };

    // Define the function pointer type matching InternetConnectA's signature
    let internet_connect: unsafe extern "system" fn(
        isize,     // HINTERNET hInternet
        *const i8, // lpszServerName
        u16,       // nServerPort
        *const i8, // lpszUserName
        *const i8, // lpszPassword
        i32,       // dwService
        u32,       // dwFlags
        u32,       // lpdwReserved
    ) -> isize;

    let connect_ret: Option<isize>;
    unsafe {
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetConnectA",
            internet_connect,
            connect_ret,
            handle,
            server_name.as_ptr(),
            80u16,
            std::ptr::null(),
            std::ptr::null(),
            3i32, // INTERNET_SERVICE_HTTP
            0u32,
            0u32
        );
    }

    let connect_handle = match connect_ret {
        Some(h) if h != 0 => h,
        _ => panic!("InternetConnectA failed"),
    };


    // Define the function pointer type matching HttpOpenRequestA's signature
    let http_open_request: unsafe extern "system" fn(
        isize,            // HINTERNET hConnect
        *const i8,        // lpszVerb
        *const i8,        // lpszObjectName
        *const i8,        // lpszVersion
        *const i8,        // lpszReferer
        *const *const i8, // lplpszAcceptTypes
        u32,              // dwFlags
        u32,              // dwContext
    ) -> isize;

    let request_ret: Option<isize>;
    unsafe {
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "HttpOpenRequestA",
            http_open_request,
            request_ret,
            connect_handle,
            method.as_ptr(),
            endpoint.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0u32,
            0u32
        );
    }

    let request_handle = match request_ret {
        Some(h) if h != 0 => h,
        _ => panic!("HttpOpenRequestA failed"),
    };

    // Define the function pointer type matching HttpSendRequestA's signature
    let http_send_request: unsafe extern "system" fn(
        isize,                 // HINTERNET hRequest
        *const i8,             // lpszHeaders
        u32,                   // dwHeadersLength
        *mut std::ffi::c_void, // lpOptional
        u32,                   // dwOptionalLength
    ) -> i32;

    let send_ret: Option<i32>;
    unsafe {
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "HttpSendRequestA",
            http_send_request,
            send_ret,
            request_handle,
            std::ptr::null(),
            0u32,
            std::ptr::null_mut(),
            0u32
        );
    }

    if send_ret != Some(1) {
        panic!("HttpSendRequestA failed");
    }

    // Define the function pointer type matching InternetReadFile's signature
    let internet_read_file: unsafe extern "system" fn(
        isize,                 // HINTERNET hFile
        *mut std::ffi::c_void, // lpBuffer
        u32,                   // dwNumberOfBytesToRead
        *mut u32               // lpdwNumberOfBytesRead
    ) -> i32;

    let mut buffer = vec![0u8; 1024];
    let mut bytes_read: u32 = 0;
    let read_ret: Option<i32>;
    unsafe {
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetReadFile",
            internet_read_file,
            read_ret,
            request_handle,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len() as u32,
            &mut bytes_read
        );
    }

    if read_ret != Some(1) {
        panic!("InternetReadFile failed");
    }

    buffer.truncate(bytes_read as usize);
    let ip = String::from_utf8(buffer).expect("Failed to convert response to string");

    // Define the function pointer type matching InternetCloseHandle's signature
    let mut internet_close_handle: unsafe extern "system" fn(
        isize, // HINTERNET hInternet
    ) -> i32;

    // Close the handles using InternetCloseHandle
    unsafe {
        let mut close_ret: Option<i32>;

        // Close the handle opened by InternetOpenA
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetCloseHandle",
            internet_close_handle,
            close_ret,
            handle
        );

        // Close the handle opened by InternetConnectA
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetCloseHandle",
            internet_close_handle,
            close_ret,
            connect_handle
        );

        // Close the handle opened by HttpOpenRequestA
        dinvoke_rs::dinvoke::dynamic_invoke!(
            module_name,
            "InternetCloseHandle",
            internet_close_handle,
            close_ret,
            request_handle
        );
    }

    ip
}
