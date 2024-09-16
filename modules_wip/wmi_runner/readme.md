### WMI Query Runner

A simple command-line tool to run WMI (Windows Management Instrumentation) queries on Windows systems.

#### Features

- Run custom WMI queries
- Execute predefined queries for common system information
- User-friendly interface with help command

#### Usage

1. Run the program
2. Enter a query number (1-20) for predefined queries
3. Or enter a custom WMI query
4. Type 'help' to see available predefined queries
5. Type 'q' to quit the program

#### Predefined Queries

The tool includes 20 predefined queries covering:

- System Information
- Hardware Information
- Network Information
- User and Group Information
- Software and Process Information
- Security and Event Information

#### Requirements

- Windows operating system
- Rust programming environment

#### Building

1. Clone the repository
2. Run `cargo build` to build the project
3. Run `cargo run` to run the program

#### Example

```
Enter your WMI query, a predefined query number, 'help' for options, or 'q' to quit.
> 1
Caption: Microsoft Windows 10 Pro
Version: 10.0.19045
```

#### Example custom query

```
> SELECT * FROM Win32_UserAccount
Name: Administrator
```

