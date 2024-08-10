use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
use windows::Win32::System::Threading::{PEB, TEB};
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use std::arch::asm;
use std::ffi::c_void;

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
// The second step is to get the PEB
// The third step is to get the LDR_DATA_TABLE_ENTRY
// The fourth step is to get the DLL base address
// The fifth step is to get the function addresses
// The sixth step is to call the functions

// The first step is to get the TEB by calling NtCurrentTEB

#[macro_use]
extern crate memoffset;

macro_rules! container_of {
    ($ptr:expr, $type:ty, $field:ident) => {{
        (($ptr as usize) - offset_of!($type, $field)) as *const $type
    }};
}

#[inline]
pub fn get_teb() -> *const TEB {
    let teb: *const TEB;
    unsafe {
        asm!("mov {}, gs:[0x30]", out(reg) teb); // x64 specific
    }
    teb
}

use std::os::raw::{c_long, c_ulong};
use std::ptr::null_mut;

type HANDLE = *mut c_void;

pub fn get_dll_address(dll_name: String, teb: *const TEB) -> Option<*const c_void> {
    let mut peb_address: *const PEB = std::ptr::null();
    let dll_name_lower = dll_name.to_lowercase(); // Convert the input dll_name to lowercase
    unsafe {
        if !teb.is_null() {
            peb_address = (*teb).ProcessEnvironmentBlock;
            let ldr_data = (*peb_address).Ldr;
            if !ldr_data.is_null() {
                let list_entry = (*ldr_data).InMemoryOrderModuleList.Flink;
                if !list_entry.is_null() {
                    let mut current_entry =
                        container_of!(list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    loop {
                        let dll_base = (*current_entry).DllBase;
                        let dll_name_in_memory = (*current_entry).FullDllName.Buffer.as_ptr();
                        let dll_name_len = (*current_entry).FullDllName.Length as usize / 2;

                        // Convert the DLL name to a Rust string and make it lowercase for case-insensitive comparison
                        let dll_name_in_memory = std::slice::from_raw_parts(dll_name_in_memory, dll_name_len);
                        let dll_name_in_memory = String::from_utf16_lossy(dll_name_in_memory).to_lowercase();

                        if dll_name_in_memory.ends_with(&dll_name_lower) {
                            return Some(dll_base);
                        }

                        // Move to the next entry
                        let next_entry = (*current_entry).InMemoryOrderLinks.Flink;
                        if next_entry == list_entry {
                            // We've looped back to the start of the list, so the DLL was not found
                            break;
                        }
                        current_entry = container_of!(next_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    }
                }
            }
        }
    }
    None
}

pub fn get_function_address(ntdll_base: *const c_void, function_name: &str) -> Option<*const c_void> {
    unsafe {
        let dos_header = &*(ntdll_base as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((ntdll_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let export_directory_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
        let export_directory = &*((ntdll_base as usize + export_directory_rva as usize)
            as *const IMAGE_EXPORT_DIRECTORY);

        let names_rva = export_directory.AddressOfNames;
        let functions_rva = export_directory.AddressOfFunctions;
        let ordinals_rva = export_directory.AddressOfNameOrdinals;

        let names = std::slice::from_raw_parts(
            (ntdll_base as usize + names_rva as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );
        let ordinals = std::slice::from_raw_parts(
            (ntdll_base as usize + ordinals_rva as usize) as *const u16,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let name_ptr = (ntdll_base as usize + names[i] as usize) as *const u8;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_str()
                .unwrap_or_default();
            if name == function_name {
                let ordinal = ordinals[i] as usize;
                let function_rva =
                    *((ntdll_base as usize + functions_rva as usize) as *const u32).add(ordinal);
                return Some((ntdll_base as usize + function_rva as usize) as *const c_void);
            }
        }
    }
    None
}

// Function to get the current process handle
pub fn get_current_process_handle(peb: *const PEB) -> HANDLE {
    // NtCurrentProcess is a pseudo-handle that always represents the current process.
    // It's a special constant that doesn't need to be closed.
    const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;

    // Return the pseudo-handle for the current process
    NT_CURRENT_PROCESS
}

//use std::ffi::c_void;

pub fn list_all_dlls(teb: *const TEB) -> Vec<(String, *mut c_void)> {
    let mut dll_list = Vec::new();
    let mut peb_address: *const PEB = std::ptr::null();
    unsafe {
        if !teb.is_null() {
            peb_address = (*teb).ProcessEnvironmentBlock;
            let ldr_data = (*peb_address).Ldr;
            if !ldr_data.is_null() {
                let list_entry = (*ldr_data).InMemoryOrderModuleList.Flink;
                if !list_entry.is_null() {
                    let mut current_entry = container_of!(list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    loop {
                        let dll_base = (*current_entry).DllBase;
                        let dll_name_in_memory = (*current_entry).FullDllName.Buffer.as_ptr();
                        let dll_name_len = (*current_entry).FullDllName.Length as usize / 2;

                        // Convert the DLL name to a Rust string
                        let dll_name_in_memory = std::slice::from_raw_parts(dll_name_in_memory, dll_name_len);
                        let dll_name = String::from_utf16_lossy(dll_name_in_memory);

                        // Add the DLL name and base address to the list
                        dll_list.push((dll_name, dll_base));

                        // Move to the next entry
                        let next_entry = (*current_entry).InMemoryOrderLinks.Flink;
                        if next_entry == list_entry {
                            // We've looped back to the start of the list
                            break;
                        }
                        current_entry = container_of!(next_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    }
                }
            }
        }
    }
    dll_list
}
