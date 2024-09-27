mod proto;
mod func;
#[macro_use]
extern crate litcrypt;
 
use_litcrypt!();

fn main() {
    proto::Pick();
}
