use std::io::{self, Write};

fn main() {
    println!("Welcome to the WMI Query Runner!");
    println!("This is a simple tool to run WMI queries on a Windows system.");
    println!("");
    //2024 @teach2breach
    println!("Enter your WMI query, a predefined query number, 'help' for options, or 'q' to quit.");

    // Define predefined queries
    let predefined_queries: Vec<(&str, &str)> = vec![
        ("1", "SELECT * FROM Win32_Group"),
        ("2", "SELECT Name, ProcessId FROM Win32_Process"),
        ("3", "SELECT Caption, FreeSpace, Size FROM Win32_LogicalDisk"),
        // Add more predefined queries as needed
    ];

    // Function to print available predefined queries
    let print_help = || {
        println!("\nPredefined queries:");
        for (key, query) in &predefined_queries {
            println!("{}: {}", key, query);
        }
        println!("\nEnter 'help' to see this list again.");
        println!("Enter 'q' to quit.");
        println!();
    };

    // Print help at the start
    print_help();

    loop {
        print!("WMI Query > ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        match input.to_lowercase().as_str() {
            "q" => {
                println!("Goodbye!");
                break;
            }
            "help" => {
                print_help();
                continue;
            }
            _ => {
                let query = predefined_queries
                    .iter()
                    .find(|&&(key, _)| key == input)
                    .map(|&(_, q)| q)
                    .unwrap_or(input);
                let result = wmi_runner::run_wmi_query(vec![query]);
                println!("Result:\n{}", result);
                println!();
            }
        }
    }
}
