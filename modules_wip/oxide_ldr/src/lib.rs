use clroxide::clr::Clr;
use std::fs;

#[macro_use]
extern crate litcrypt;

use_litcrypt!("ageofmachine");

pub fn dotloader(content: Vec<u8>, args: String) -> Result<String, String> {
    let sent_args: Vec<String> = if !args.is_empty() {
        args.split_whitespace().map(String::from).collect()
    } else {
        Vec::new()
    };

    let contents = content;
    let mut clr = Clr::new(contents, sent_args)?;

    let results = clr.run()?;

    Ok(results)
}