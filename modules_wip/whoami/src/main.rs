#[macro_use]
extern crate litcrypt;

use_litcrypt!("ageofmachine");

use whoami::get_username_ntapi;

fn main() {

    //println!("calling get_username_ntapi");
    let user = match get_username_ntapi() {
        Ok(username) => username,
        Err(error) => {
            eprintln!("Error: {}", error);
            return;
        }
    };
    println!("Username + Privs: {}", user);
}