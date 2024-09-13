use crate::func;

use_litcrypt!();

#[no_mangle]
pub extern "system" fn Pick() {
    println!("Hello, world!");

    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");

    if ntdll == 0 {
        println!("Failed to locate ntdll.dll");
        return;
    }

    let version = func::get_version(ntdll);
    println!("Version: {}", version);
}