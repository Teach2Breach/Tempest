use std::collections::HashMap;

use wmi::{COMLibrary, Variant, WMIConnection};

// Runs a WMI query with the provided query parts and returns the formatted results.
pub fn run_wmi_query(query_parts: Vec<&str>) -> String {
    // Convert the query Vec<&str> to a single query string.
    let query = query_parts.join(" ");

    //TODO remove this print statement after testing
    println!("Query: {:?}", query);
    let com_con = match COMLibrary::new() {
        Ok(con) => con,
        Err(_) => return "Error initializing COM Library".to_string(),
    };

    let wmi_con = match WMIConnection::new(com_con.into()) {
        Ok(con) => con,
        Err(_) => return "Error connecting to WMI".to_string(),
    };

    let results: Vec<HashMap<String, Variant>> = match wmi_con.raw_query(query) {
        Ok(results) => results,
        Err(_) => return "Error executing WMI query".to_string(),
    };

    let mut output: Vec<String> = Vec::new();

    for result in results {
        for (key, value) in result {
            let value_str = match value {
                Variant::String(s) => s.clone(),
                Variant::UI1(u) => u.to_string(),
                Variant::UI2(u) => u.to_string(),
                Variant::UI4(u) => u.to_string(),
                Variant::UI8(u) => u.to_string(),
                Variant::I1(i) => i.to_string(),
                Variant::I2(i) => i.to_string(),
                Variant::I4(i) => i.to_string(),
                Variant::I8(i) => i.to_string(),
                Variant::R4(f) => f.to_string(),
                Variant::R8(f) => f.to_string(),
                Variant::Bool(b) => b.to_string(),
                Variant::Array(arr) => arr.iter().map(|v| match v {
                    Variant::String(vs) => vs.clone(),
                    Variant::UI1(u) => u.to_string(),
                    Variant::UI2(u) => u.to_string(),
                    Variant::UI4(u) => u.to_string(),
                    Variant::UI8(u) => u.to_string(),
                    Variant::I1(i) => i.to_string(),
                    Variant::I2(i) => i.to_string(),
                    Variant::I4(i) => i.to_string(),
                    Variant::I8(i) => i.to_string(),
                    Variant::R4(f) => f.to_string(),
                    Variant::R8(f) => f.to_string(),
                    Variant::Bool(b) => b.to_string(),
                    Variant::Null => "null".to_string(),
                    _ => "Unsupported Variant type in array".to_string(),
                }).collect::<Vec<_>>().join(", "),
                Variant::Null => "null".to_string(),
                _ => format!("{:?}", value),  // Use debug formatting for other variants
            };
            output.push(format!("{}: {}", key, value_str));
        }
    }

    if output.is_empty() {
        "No results found".to_string()
    } else {
        format!("\n{}", output.join("\n"))
    }
}