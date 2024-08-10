#![allow(dead_code)] 
mod proto;
#[macro_use]
extern crate litcrypt;
use_litcrypt!("ageofmachine");

pub extern fn main() {
    proto::Pick();
}