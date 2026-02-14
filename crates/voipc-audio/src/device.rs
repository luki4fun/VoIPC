use anyhow::Result;
use cpal::traits::{DeviceTrait, HostTrait};

/// Information about an audio device.
#[derive(Debug, Clone)]
pub struct AudioDeviceInfo {
    pub name: String,
    pub is_default: bool,
}

/// List available audio input (microphone) devices.
pub fn list_input_devices() -> Result<Vec<AudioDeviceInfo>> {
    let host = cpal::default_host();
    let default_name = host
        .default_input_device()
        .and_then(|d| d.name().ok())
        .unwrap_or_default();

    let mut devices = Vec::new();
    for device in host.input_devices()? {
        if let Ok(name) = device.name() {
            devices.push(AudioDeviceInfo {
                is_default: name == default_name,
                name,
            });
        }
    }
    Ok(devices)
}

/// List available audio output (speaker) devices.
pub fn list_output_devices() -> Result<Vec<AudioDeviceInfo>> {
    let host = cpal::default_host();
    let default_name = host
        .default_output_device()
        .and_then(|d| d.name().ok())
        .unwrap_or_default();

    let mut devices = Vec::new();
    for device in host.output_devices()? {
        if let Ok(name) = device.name() {
            devices.push(AudioDeviceInfo {
                is_default: name == default_name,
                name,
            });
        }
    }
    Ok(devices)
}

/// Find an input device by name, falling back to default.
pub fn get_input_device(name: Option<&str>) -> Result<cpal::Device> {
    let host = cpal::default_host();

    if let Some(name) = name {
        for device in host.input_devices()? {
            if device.name().ok().as_deref() == Some(name) {
                return Ok(device);
            }
        }
    }

    host.default_input_device()
        .ok_or_else(|| anyhow::anyhow!("no input device available"))
}

/// Find an output device by name, falling back to default.
pub fn get_output_device(name: Option<&str>) -> Result<cpal::Device> {
    let host = cpal::default_host();

    if let Some(name) = name {
        for device in host.output_devices()? {
            if device.name().ok().as_deref() == Some(name) {
                return Ok(device);
            }
        }
    }

    host.default_output_device()
        .ok_or_else(|| anyhow::anyhow!("no output device available"))
}
