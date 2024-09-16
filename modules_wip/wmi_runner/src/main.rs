use std::io::{self, Write};

fn main() {
    println!("Welcome to the WMI Query Runner!");
    println!("This is a simple tool to run WMI queries on a Windows system.");
    println!("");
    //2024 @teach2breach
    println!("Enter your WMI query, a predefined query number, 'help' for options, or 'q' to quit.");

    // Define predefined queries
    let predefined_queries: Vec<(&str, &str)> = vec![
        // System Information
        ("1", "SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem"),
        ("2", "SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem"),
        ("3", "SELECT Name, Manufacturer, SerialNumber FROM Win32_BIOS"),
        ("4", "SELECT * FROM Win32_TimeZone"),
        
        // Hardware Information
        ("5", "SELECT Caption, DeviceID, Size FROM Win32_DiskDrive"),
        ("6", "SELECT Caption, FreeSpace, Size FROM Win32_LogicalDisk"),
        ("7", "SELECT Name, VideoProcessor, AdapterRAM FROM Win32_VideoController"),
        ("8", "SELECT Name, Manufacturer, MaxClockSpeed, NumberOfCores FROM Win32_Processor"),
        
        // Network Information
        ("9", "SELECT IPAddress, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"),
        ("10", "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled=True"),
        ("11", "SELECT * FROM Win32_NetworkLoginProfile"),
        
        // User and Group Information
        ("12", "SELECT * FROM Win32_UserAccount"),
        ("13", "SELECT * FROM Win32_Group"),
        ("14", "SELECT * FROM Win32_GroupUser"),
        
        // Software and Process Information
        ("15", "SELECT Name, Version, Vendor FROM Win32_Product"),
        ("16", "SELECT Name, ExecutablePath, ProcessId FROM Win32_Process"),
        ("17", "SELECT * FROM Win32_Service"),
        
        // Security and Event Information
        ("18", "SELECT * FROM Win32_LoggedOnUser"),
        ("19", "SELECT * FROM Win32_QuickFixEngineering"),  // Installed updates/patches
        ("20", "SELECT * FROM Win32_StartupCommand")
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
