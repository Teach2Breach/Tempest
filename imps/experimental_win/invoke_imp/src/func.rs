use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

// Define RtlGetVersion function type
type RtlGetVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;

pub fn get_version(ntdll: usize) -> String {
    unsafe {
        let function_ptr = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlGetVersion");
        let function_type: RtlGetVersion = std::mem::transmute(function_ptr as usize);
        let ret: i32;

        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            dwMajorVersion: 0,
            dwMinorVersion: 0,
            dwBuildNumber: 0,
            dwPlatformId: 0,
            szCSDVersion: [0; 128],
        };

        ret = function_type(&mut version_info);

        match ret {
            0 => {
                format!("Windows {}.{}.{}", 
                    version_info.dwMajorVersion, 
                    version_info.dwMinorVersion, 
                    version_info.dwBuildNumber)
            },
            status => format!("Error: NTSTATUS == {:X}", status as u32),
        }
    }
}