use std::arch::asm;
use std::ffi::c_void;
use std::os::raw::{c_long, c_ulong};
use std::ptr::null_mut;
use windows::Win32::System::Threading::{PEB, TEB};

use noldr::{get_dll_address, list_all_dlls};
use noldr::get_function_address;
use noldr::get_teb;
use noldr::get_current_process_handle;


//println!("Hello, world!");

/*Progranm description

 A program which aims to use a novel technique to locate functions and function addresses inside the already loaded
 (shared) ntdll. in order to do this, we'll need to first locate and walk the PEB or Process Environment Block.
We could start by calling NtQueryInformationProcess, which is fairly opsec safe, but we'll try to get weirder
and call an ancient windows macro NtCurrentTEB which will read directly from the process memory of the CPU
to get a pointer to the TEB, which we can use to get a pointer to the PEB. */

// NtCurrentTEB is a macro that reads the FS register to get the TEB
// The TEB is a structure that contains a pointer to the PEB
// The PEB is a structure that contains a pointer to the LDR_DATA_TABLE_ENTRY
// The LDR_DATA_TABLE_ENTRY is a structure that contains a pointer to the DLL base address
// The DLL base address is the base address of the ntdll.dll
// The ntdll.dll contains the function addresses of the functions we want to call

// The first step is to get the TEB
// The TEB is located at the FS register
// The FS register is a segment register that points to the Thread Environment Block (TEB)
// The TEB is a structure that contains a pointer to the PEB
// The PEB is a structure that contains a pointer to the LDR_DATA_TABLE_ENTRY
// The LDR_DATA_TABLE_ENTRY is a structure that contains a pointer to the DLL base address
// The DLL base address is the base address of the ntdll.dll
// The ntdll.dll contains the function addresses of the functions we want to call

// The second step is to get the PEB

// The third step is to get the LDR_DATA_TABLE_ENTRY

// The fourth step is to get the DLL base address

// The fifth step is to get the function addresses

// The sixth step is to call the functions

// For this proof of concept, we will call NtCreateProcess and launch calculator

// The first step is to get the TEB by calling NtCurrentTEB

#[macro_use]
extern crate memoffset;

macro_rules! container_of {
    ($ptr:expr, $type:ty, $field:ident) => {{
        (($ptr as usize) - offset_of!($type, $field)) as *const $type
    }};
}

type PHANDLE = *mut HANDLE;
type ACCESS_MASK = u32;
type POBJECT_ATTRIBUTES = *mut c_void;
type HANDLE = *mut c_void;
type BOOLEAN = u8;
type NTSTATUS = c_long;

type NtCreateProcessType = unsafe extern "system" fn(
    ProcessHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ParentProcess: HANDLE,
    InheritObjectTable: BOOLEAN,
    SectionHandle: HANDLE,
    DebugPort: HANDLE,
    ExceptionPort: HANDLE,
) -> NTSTATUS;

fn main() {

    //gather command line arguments into an array
/* 
    let args: Vec<String> = std::env::args().collect();

    //if no args are given, print usage and exit

    if args.len() < 3 {
        println!("Usage: noldr <dll_name> <function_name>");
        std::process::exit(1);
    }

    let dll_name = &args[1];
    let function_name = &args[2];
    */
    //println!("Hello, world!");
    /*let nt_create_process: NtCreateProcessType = unsafe {
        std::mem::transmute(noloader(
            "ntdll.dll".to_string(),
            "NtCreateProcess".to_string(),
        ))
    };*/
    let teb = get_teb();
    //return list of dlls
    let dlls = list_all_dlls(teb);
    println!("dlls: {:?}", dlls);
    let dll_base_address = get_dll_address("kERnel32.DLL".to_string(), teb).unwrap();
    println!("dll_base_address: {:?}", dll_base_address);
    /*
    let dll_base = get_dll_address(dll_name.to_string(), teb).unwrap();
    println!("dll_base: {:?}", dll_base);
    println!("function_name: {}", function_name);
    let function_address =
        get_function_address(dll_base, &function_name).unwrap();

    println!("function_address: {:?}", function_address);
    
    let mut peb_address: *const PEB = std::ptr::null();

    peb_address = unsafe { (*teb).ProcessEnvironmentBlock }; // Correct way to get PEB address

    let mut process_handle: HANDLE = null_mut();
    //let parent_process: HANDLE = null_mut();
    let parent_process = get_current_process_handle(peb_address);
    let process_attributes: *mut c_void = null_mut();
    let inherit_handles: BOOLEAN = 1;
    let section_handle: HANDLE = null_mut();
    let debug_port: HANDLE = null_mut();
    let exception_port: HANDLE = null_mut();

    let nt_create_process: NtCreateProcessType = unsafe {
        std::mem::transmute(function_address)
    };

    let status = unsafe {
        nt_create_process(
            &mut process_handle as *mut HANDLE,
            0x1FFFFF, // Desired access, adjust as needed
            process_attributes,
            parent_process,
            inherit_handles,
            section_handle,
            debug_port,
            exception_port,
        )
    };

    println!("NtCreateProcess returned: {:?}", status);
    println!("Process handle: {:?}", process_handle);
    // enable this section if you want to make sure the process is being created (check in taskman)
    //get the pid of the process
    let pid = unsafe {
        windows::Win32::System::Threading::GetProcessId(
            std::mem::transmute::<*mut c_void, windows::Win32::Foundation::HANDLE>(process_handle), // cast to HANDLE
        )
    };

    println!("Process ID: {:?}", pid);

    //next we can call NtCreateThreadEx to create a new thread in the process
    // but we'll leave that for another day
    //wait for user input to continue
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();*/
}