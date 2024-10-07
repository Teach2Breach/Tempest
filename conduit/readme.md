#### Conduit

##### Overview

Conduit is a Terminal User Interface (TUI) application that allows you to connect to an Anvil server, build implants (imps), issue tasks, and retrieve data from connected imps. This tool provides a user-friendly interface for managing and interacting with Anvil implants.

##### Known Issues

- As of 10.07.2024, there is an issue with the TUI not properly updating on some terminals when the window is resized. A temp workaround is to press F1 on your keyboard which will clear the terminal and refresh the TUI. I'm still working on a fix for this. See devlog and issue #10 for more details.

##### Features

- Connect to Anvil server securely
- Build new implants with customizable parameters
- View and manage connected implants
- Issue tasks to individual implants
- Retrieve and display output from implants
- Support for both Windows and Linux implants
- Real-time updates of implant status and output

##### Installation

1. Ensure you have Rust and Cargo installed on your system.
2. Clone this repository:
   ```
   git clone https://github.com/yourusername/conduit.git
   ```
3. Navigate to the project directory:
   ```
   cd conduit
   ```
4. Build the project:
   ```
   cargo build --release
   ```

##### Usage

1. Run the application:
   ```
   ./target/release/conduit
   ```
2. Enter the Anvil server IP address, username, and password when prompted.
3. Use the TUI to interact with the Anvil server and manage implants.

##### Commands

- `help`: Display available commands
- `build <target_os> <format> <target_ip> <target_port> <sleep> <jitter>`: Generate a new implant
- `use <session>`: Interact with a specific implant
- `q` or `quit`: Exit the program or current session

When interacting with an implant, additional commands are available based on the implant's operating system (Windows or Linux).

###### Example Build Commands

1. Build a Windows executable implant:
   ```
   build windows exe 192.168.1.19 443 2 50
   ```

2. Build a Windows implant with no loader in raw format:
   ```
   build windows_noldr raw 192.168.1.19 443 30 60
   ```

3. Build a Linux ELF implant:
   ```
   build linux elf 192.168.1.19 443 20 27
   ```

##### Configuration

The application uses a `config.toml` file for configuration. Ensure this file is present in the same directory as the executable and contains the necessary settings, including the server port.

##### Security

This application uses HTTPS for communication with the Anvil server. However, it currently accepts invalid SSL certificates. Exercise caution when using this in a production environment.