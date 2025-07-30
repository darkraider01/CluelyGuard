use libpulse_binding as pulse;
use pulse::context::{Context, FlagSet, State};
use pulse::mainloop::standard::Mainloop;
use pulse::proplist::Proplist;
use libpulse_binding::callbacks::ListResult;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;


pub fn check() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎤 Checking mic usage via PulseAudio...");

    let mut ml = Mainloop::new().ok_or("❌ Failed to create PulseAudio mainloop")?;

    let mut proplist = Proplist::new().ok_or("❌ Failed to create PulseAudio proplist")?;
    proplist
        .set_str(pulse::proplist::properties::APPLICATION_NAME, "cluelyguard-audio")
        .map_err(|_| "Failed to set application name")?;

    let mut ctx = Context::new_with_proplist(&ml, "CluelyGuard", &proplist)
        .ok_or("❌ Failed to create PulseAudio context")?;

    ctx.connect(None, FlagSet::NOFLAGS, None)
        .map_err(|_| "❌ Failed to connect PulseAudio context")?;

    let result = Arc::new(Mutex::new(false));
    let result_for_callback = Arc::clone(&result);
    let checked = Arc::new(Mutex::new(false));
    let _checked_clone = Arc::clone(&checked);

    // Wait for context to be ready and then perform the check
    loop {
        match ml.iterate(false) {
            pulse::mainloop::standard::IterateResult::Quit(_) => break,
            pulse::mainloop::standard::IterateResult::Err(_) => {
                return Err("❌ Failed to iterate mainloop".into());
            }
            pulse::mainloop::standard::IterateResult::Success(_) => {}
        }
        
        let state = ctx.get_state();
        match state {
            State::Ready => {
                if !*checked.lock().unwrap() {
                    *checked.lock().unwrap() = true;
                    
                    let introspect = ctx.introspect();
                    let result_clone = Arc::clone(&result_for_callback);
                    
                    introspect.get_source_output_info_list(move |res| {
                        match res {
                            ListResult::Item(info) => {
                                if let Some(app_name) = info.proplist.get_str("application.name") {
                                    println!("⚠️  Mic used by: {}", app_name);
                                    *result_clone.lock().unwrap() = true;
                                }
                            }
                            ListResult::End => {
                                println!("🔚 Finished checking mic sources.");
                            }
                            ListResult::Error => {
                                eprintln!("❌ Error while retrieving mic stream info.");
                            }
                        }
                    });
                }
                break;
            }
            State::Failed | State::Terminated => {
                return Err("❌ PulseAudio context failed or terminated".into());
            }
            _ => {
                // Context still connecting, continue iterating
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    // Give some time for the callback to execute
    for _ in 0..200 {
        match ml.iterate(false) {
            pulse::mainloop::standard::IterateResult::Quit(_) => break,
            pulse::mainloop::standard::IterateResult::Err(_) => {
                return Err("❌ Failed to iterate mainloop".into());
            }
            pulse::mainloop::standard::IterateResult::Success(_) => {}
        }
        thread::sleep(Duration::from_millis(10));
    }

    if !*result.lock().unwrap() {
        println!("✅ No mic usage detected.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_no_mic_usage_detected() {
        // This test assumes a clean PulseAudio environment where no applications are
        // actively using the microphone. It primarily checks that the `check()`
        // function executes without panicking and returns Ok.
        // Mocking libpulse-binding is extremely complex and outside the scope
        // of a simple unit test here.
        let result = check();
        assert!(result.is_ok(), "Mic check should pass if no mic usage is detected: {:?}", result.err());
    }

    // To test actual mic usage detection, a more sophisticated integration test
    // environment would be needed, potentially involving:
    // - A virtual audio device.
    // - A separate process simulating mic usage (e.g., recording audio).
    // - Capturing stdout/stderr to verify the "Mic used by" message.
    // This is beyond the scope of a unit test within the current setup.
}