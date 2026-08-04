use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Logger;
use actix_web::Error;
use actix_web::{App, HttpServer};
use anvil::{
    configure_conduit_routes, configure_implant_routes, generate_aes_key_material,
    init_database, load_aes_key_from_file, save_aes_key_to_file, User,
};
use clap::Parser;
use config::{Config, File};
use base64::Engine as _;
use env_logger;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::env;
use std::path::Path;
use std::sync::Arc;
use tracing::Level;
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder};

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

#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "Anvil")]
struct Args {
    #[clap(short, long)]
    debug: bool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=trace,actix_server=trace");

    env_logger::init();

    let _args: Args = Args::parse();

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

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let certificate = env::var("CERTIFICATE").expect("CERTIFICATE must be set");

    let private_key_clone = private_key.clone();
    let certificate_clone = certificate.clone();

    let aes_key_path = Path::new("aes_key.bin");
    let (aes_key, encoded_aes_key) = if aes_key_path.exists() {
        let raw = load_aes_key_from_file(aes_key_path)?;
        let encoded = anvil::crypto::CUSTOM_B64.encode(&raw);
        (raw, encoded)
    } else {
        let (raw, encoded) = generate_aes_key_material()?;
        save_aes_key_to_file(&raw, aes_key_path)?;
        (raw, encoded)
    };
    let _ = aes_key; // retained for side effect of load/generate
    std::env::set_var("AES_KEY", encoded_aes_key.clone());
    println!("AES key generated and stored.");
    println!("encoded AES key: {}", encoded_aes_key);

    let mut builder_443 = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder_443
        .set_private_key_file(&private_key, SslFiletype::PEM)
        .unwrap();
    builder_443
        .set_certificate_chain_file(&certificate)
        .unwrap();

    let mut builder_8443 = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder_8443
        .set_private_key_file(private_key_clone, SslFiletype::PEM)
        .unwrap();
    builder_8443
        .set_certificate_chain_file(certificate_clone)
        .unwrap();

    let database_url = "./my_database.db";
    let users: Vec<User> = settings
        .get_array("users")
        .unwrap()
        .into_iter()
        .map(|u| u.try_into().unwrap())
        .collect();
    let db = init_database(Path::new(database_url), &users).expect("Cannot open database");

    let build_toolchain: String = settings
        .get("build.toolchain")
        .unwrap_or_else(|_| String::from("nightly-2025-03-03"));
    std::env::set_var("RUSTUP_TOOLCHAIN", &build_toolchain);

    let implant_port: u16 = settings
        .get("server.implant_port")
        .expect("Failed to get implant_port from config");
    let conduit_port: u16 = settings
        .get("server.conduit_port")
        .expect("Failed to get conduit_port from config");

    let outputs_max_rows: u64 = settings
        .get_int("server.outputs_max_rows")
        .map(|i| (i.max(0)) as u64)
        .unwrap_or(0);
    std::env::set_var("TEMPEST_OUTPUTS_MAX_ROWS", outputs_max_rows.to_string());

    use std::thread;

    let db_443 = Arc::clone(&db);
    let implant_server = thread::spawn(move || {
        let sys = actix_rt::System::new;
        let srv = HttpServer::new(move || {
            let logger = Logger::default();
            App::new()
                .wrap(logger)
                .configure(|cfg| configure_implant_routes(cfg, db_443.clone()))
        })
        .bind_openssl(format!("0.0.0.0:{}", implant_port), builder_443)?
        .run();
        sys().block_on(srv)
    });

    let db_8443 = Arc::clone(&db);
    let conduit_server = thread::spawn(move || {
        let sys = actix_rt::System::new;
        let srv = HttpServer::new(move || {
            let logger = Logger::default();
            App::new()
                .wrap(logger)
                .configure(|cfg| configure_conduit_routes(cfg, db_8443.clone()))
        })
        .bind_openssl(format!("0.0.0.0:{}", conduit_port), builder_8443)?
        .run();
        sys().block_on(srv)
    });

    let _ = implant_server.join().unwrap()?;
    let _ = conduit_server.join().unwrap()?;

    Ok(())
}
