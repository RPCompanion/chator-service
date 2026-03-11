use retour::static_detour;
use std::mem;

use crate::lib_only::submit_message;
use crate::share::CaptureMessage;
use crate::share::raw_dice_roll::RawDiceRoll;

const ROLL_HANDLER_RELATIVE_ADDRESS: isize = 0x0e561d0;

static_detour! {
    static RollHook: extern "C" fn(*mut u16, i32, *const *const u16, i32) -> i64;
}

/// Reads a null-terminated UTF-16 (wchar_t*) pointer into a Rust String.
unsafe fn read_wstr(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
            if len > 512 {
                return None;
            }
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).ok()
    }
}

pub fn begin_detour(base_address: isize) {
    unsafe {
        let target: extern "C" fn(*mut u16, i32, *const *const u16, i32) -> i64 =
            mem::transmute(base_address + ROLL_HANDLER_RELATIVE_ADDRESS);

        match RollHook.initialize(target, roll_handler_detour) {
            Ok(_) => {
                submit_message(CaptureMessage::Info(
                    "Dice roll detour initialized".to_string(),
                ));
                RollHook.enable().unwrap();
            }
            Err(_) => {
                submit_message(CaptureMessage::CaptureError(
                    "Failed to initialize dice roll detour".to_string(),
                ));
            }
        }
    }
}

/// Detour for the template parameter substitution function (FUN_140e561d0).
///
/// Signature: (wchar_t* output_buf, int buf_size, wchar_t** param_array, int param_count) -> i64
///
/// For dice rolls:
///   - output_buf contains template: "[Random]: <<1>> rolls <<2>>"
///   - param_array[0] = player name (e.g., "Elizala")
///   - param_array[1] = result text (e.g., "(1-100): 42")
fn roll_handler_detour(
    output_buf: *mut u16,
    buf_size: i32,
    param_array: *const *const u16,
    param_count: i32,
) -> i64 {
    submit_message(CaptureMessage::Info(format!(
        "roll_handler_detour called: param_count={}, output_buf_null={}, param_array_null={}",
        param_count,
        output_buf.is_null(),
        param_array.is_null()
    )));

    if param_count == 2 && !output_buf.is_null() && !param_array.is_null() {
        unsafe {
            if let Some(template) = read_wstr(output_buf as *const u16) {
                submit_message(CaptureMessage::Info(format!(
                    "roll_handler_detour template: \"{}\"",
                    template
                )));
                if template.contains("rolls") && template.contains("Random") {
                    let player_name = read_wstr(*param_array);
                    let result_text = read_wstr(*param_array.add(1));

                    submit_message(CaptureMessage::Info(format!(
                        "roll_handler_detour matched! player={:?}, result={:?}",
                        player_name, result_text
                    )));

                    if let (Some(player), Some(result)) = (player_name, result_text) {
                        submit_message(CaptureMessage::Roll(RawDiceRoll::new(player, result)));
                    }
                }
            } else {
                submit_message(CaptureMessage::Info(
                    "roll_handler_detour: failed to read template from output_buf".to_string(),
                ));
            }
        }
    }

    RollHook.call(output_buf, buf_size, param_array, param_count)
}

pub fn end_detour() {
    unsafe {
        RollHook.disable().unwrap();
    }
}
