use clroxide::clr::Clr;
use std::fs;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();

    // Check if the file path argument is provided
    if args.len() < 2 {
        return Err("Usage: program_name <path to file> [additional arguments]".to_string());
    }

    // Read file contents, handling potential errors
    let contents = fs::read(&args[1])
        .map_err(|e| format!("Failed to read file '{}': {}", &args[1], e))?;

    // If additional arguments are provided, use them; otherwise, pass an empty string
    let additional_args = if args.len() > 2 { &args[2] } else { "" };

    // Call dotloader with contents and additional arguments
    let result = oxide_ldr::dotloader(contents, additional_args.to_string());

    // Match on the result to print success or error messages
    match result {
        Ok(results) => {
            println!("[*] Results:\n\n{:?}", results);
        },
        Err(e) => {
            println!("[*] Error:\n\n{:}", e);
        }
    }

    Ok(())
}