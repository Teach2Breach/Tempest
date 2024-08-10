use coffee_ldr::loader::Coffee;

fn main() {
    /*
    let whoami_bof: [u8; 6771] = [
        0x64, 0x86, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x14, 0x00, 0x00, 0x33, 0x00, 0x00,
        ...
    ];*/

    //instead of defining the buffer in the code, you can read it from a file
    //but we want to read a compiled object file, such as whoami.x64.o
    //as pass it as a slice::from_raw_parts to the Coffee::new() function
    let whoami_bof_vec = std::fs::read("dir.x64.o").unwrap();
    let whoami_bof_slice =
        unsafe { std::slice::from_raw_parts(whoami_bof_vec.as_ptr(), whoami_bof_vec.len()) };

    //println!("whoami_bof_slice: {:?}", whoami_bof_slice);
    let arguments = br"wstr:C:\\Users\\kirkt"; // Your arguments as a byte array
    let arguments_ptr = arguments.as_ptr(); // Pointer to the arguments
    let arguments_size = arguments.len(); // Size of the arguments

    let _ = Coffee::new(&whoami_bof_slice)
        .unwrap()
        .execute(Some(arguments_ptr), Some(arguments_size), None);}
