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

/// Find the input device the user chose by name, or the system's default when
/// they chose none.
pub fn get_input_device(name: Option<&str>) -> Result<cpal::Device> {
    let host = cpal::default_host();
    pick_input(
        name,
        || Ok(host.input_devices()?.map(|d| (d.name().ok(), d)).collect()),
        || host.default_input_device(),
    )
}

/// The input device for `name` among what `listed` gives, or `default` for none.
///
/// A chosen device that is not there is an error, never the default: the
/// capture's reopen after an unplug used to find the laptop's own microphone
/// (or a webcam's) in its place within a second and send from it, saying
/// nothing, and the next push-to-talk press did the same (dive 6 F8). Pulling
/// the headset's plug is a way to stop talking. The error is said, and the
/// reopen keeps trying the chosen device until it is back.
fn pick_input<D>(
    name: Option<&str>,
    listed: impl FnOnce() -> Result<Vec<(Option<String>, D)>>,
    default: impl FnOnce() -> Option<D>,
) -> Result<D> {
    let Some(name) = name else {
        return default().ok_or_else(|| anyhow::anyhow!("no input device available"));
    };
    listed()?
        .into_iter()
        .find(|(found, _)| found.as_deref() == Some(name))
        .map(|(_, device)| device)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the microphone \"{name}\" is not connected: plug it back in, \
                 or choose another one in Settings"
            )
        })
}

/// Whether the input device can open a stream at `rate` with the given
/// sample format and channel count (checked against its advertised config
/// ranges — no throwaway stream is opened).
pub fn input_supports_rate(
    device: &cpal::Device,
    format: cpal::SampleFormat,
    channels: u16,
    rate: u32,
) -> bool {
    device
        .supported_input_configs()
        .map(|mut cfgs| {
            cfgs.any(|c| {
                c.channels() == channels
                    && c.sample_format() == format
                    && c.min_sample_rate().0 <= rate
                    && rate <= c.max_sample_rate().0
            })
        })
        .unwrap_or(false)
}

/// Whether the output device can open a stream at `rate` with the given
/// sample format and channel count.
pub fn output_supports_rate(
    device: &cpal::Device,
    format: cpal::SampleFormat,
    channels: u16,
    rate: u32,
) -> bool {
    device
        .supported_output_configs()
        .map(|mut cfgs| {
            cfgs.any(|c| {
                c.channels() == channels
                    && c.sample_format() == format
                    && c.min_sample_rate().0 <= rate
                    && rate <= c.max_sample_rate().0
            })
        })
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(names: &[&'static str]) -> Result<Vec<(Option<String>, &'static str)>> {
        Ok(names.iter().map(|n| (Some(n.to_string()), *n)).collect())
    }

    /// The headset the user chose is unplugged: the capture's reopen found the laptop's own
    /// microphone instead, opened it within a second and said nothing (dive 6 F8).
    #[test]
    fn a_chosen_microphone_that_is_gone_is_not_replaced() {
        let picked = pick_input(
            Some("Headset"),
            || listed(&["Built-in"]),
            || Some("Built-in"),
        );
        let err = picked.expect_err("the default stood in for the chosen microphone");
        assert!(err.to_string().contains("Headset"), "{err}");
        // Controls: the chosen one when it is there; the default when none is chosen
        let picked = pick_input(
            Some("Headset"),
            || listed(&["Built-in", "Headset"]),
            || Some("Built-in"),
        );
        assert_eq!(picked.unwrap(), "Headset");
        let picked = pick_input(
            None,
            || panic!("no list read for no name"),
            || Some("Built-in"),
        );
        assert_eq!(picked.unwrap(), "Built-in");
        assert!(pick_input::<&str>(None, || listed(&[]), || None).is_err());
    }
}
