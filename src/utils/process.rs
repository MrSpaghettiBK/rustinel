//! Process utilities (Windows-only helpers).

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

#[cfg(windows)]
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
#[cfg(windows)]
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut u8,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

/// Query a process command line from a process handle.
/// Returns None if the command line is unavailable or the process exits.
#[cfg(windows)]
pub fn query_process_command_line_from_handle(handle: HANDLE) -> Option<String> {
    unsafe {
        let mut return_length = 0u32;
        let status = NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH || return_length == 0 {
            return None;
        }

        let mut buffer = vec![0u8; return_length as usize];
        let status = NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr(),
            return_length,
            &mut return_length,
        );
        if status != 0 {
            return None;
        }

        if buffer.len() < std::mem::size_of::<UNICODE_STRING>() {
            return None;
        }

        let unicode = &*(buffer.as_ptr() as *const UNICODE_STRING);
        if unicode.Length == 0 || unicode.Buffer.is_null() {
            return None;
        }

        let len = (unicode.Length / 2) as usize;
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_end = buffer_start + buffer.len();
        let cmd_ptr = unicode.Buffer.0 as usize;
        let cmd_end = cmd_ptr.saturating_add(len.saturating_mul(2));
        if cmd_ptr < buffer_start || cmd_end > buffer_end {
            return None;
        }

        let slice = std::slice::from_raw_parts(unicode.Buffer.0, len);
        let cmd = String::from_utf16_lossy(slice)
            .trim_end_matches('\0')
            .to_string();
        if cmd.is_empty() {
            None
        } else {
            Some(cmd)
        }
    }
}

/// Query a process command line by PID (best-effort).
#[cfg(windows)]
pub fn query_process_command_line(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    if handle.is_invalid() {
        return None;
    }

    let cmd = query_process_command_line_from_handle(handle);
    let _ = unsafe { CloseHandle(handle) };
    cmd
}

#[cfg(not(windows))]
pub fn query_process_command_line(_pid: u32) -> Option<String> {
    None
}
