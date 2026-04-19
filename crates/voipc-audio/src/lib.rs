#[cfg(not(target_os = "android"))]
pub mod capture;
pub mod decoder;
pub mod denoise;
#[cfg(not(target_os = "android"))]
pub mod device;
pub mod encoder;
pub mod jitter;
pub mod mixer;
#[cfg(not(target_os = "android"))]
pub mod playback;
pub mod vad;

// Android audio via Oboe (AAudio/OpenSL ES)
#[cfg(target_os = "android")]
pub mod capture {
    use anyhow::Result;
    use oboe::{
        AudioInputCallback, AudioInputStreamSafe, AudioStream, AudioStreamBase,
        AudioStreamBuilder, DataCallbackResult, InputPreset, Mono, PerformanceMode,
        SharingMode,
    };
    use ringbuf::traits::{Producer, Split};
    use ringbuf::HeapRb;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const TARGET_SAMPLE_RATE: u32 = 48_000;
    const CAPTURE_BUFFER_SIZE: usize = 48_000 / 5; // ~200ms

    struct OboeCapture {
        producer: ringbuf::HeapProd<f32>,
        active: Arc<AtomicBool>,
    }

    impl AudioInputCallback for OboeCapture {
        type FrameType = (f32, Mono);

        fn on_audio_ready(
            &mut self,
            _stream: &mut dyn AudioInputStreamSafe,
            audio_data: &[f32],
        ) -> DataCallbackResult {
            if !self.active.load(Ordering::Relaxed) {
                return DataCallbackResult::Continue;
            }
            // Push samples into ring buffer (lock-free, drops oldest if full)
            let _ = self.producer.push_slice(audio_data);
            DataCallbackResult::Continue
        }

        fn on_error_after_close(
            &mut self,
            _stream: &mut dyn AudioInputStreamSafe,
            error: oboe::Error,
        ) {
            tracing::error!("Oboe input stream error: {:?}", error);
        }
    }

    pub struct CaptureStream {
        _stream: oboe::AudioStreamAsync<oboe::Input, OboeCapture>,
        sample_rate: u32,
        active: Arc<AtomicBool>,
    }

    // SAFETY: The Oboe stream is managed internally and the callback uses
    // lock-free ring buffers. CaptureStream is only used from the main thread.
    unsafe impl Send for CaptureStream {}

    pub fn start_capture(
        _device_name: Option<&str>,
    ) -> Result<(CaptureStream, ringbuf::HeapCons<f32>)> {
        let rb = HeapRb::<f32>::new(CAPTURE_BUFFER_SIZE);
        let (producer, consumer) = rb.split();
        let active = Arc::new(AtomicBool::new(true));

        let callback = OboeCapture {
            producer,
            active: active.clone(),
        };

        // Use Unprocessed preset — we apply our own RNNoise denoising
        let mut stream = AudioStreamBuilder::default()
            .set_input()
            .set_sample_rate(TARGET_SAMPLE_RATE as i32)
            .set_mono()
            .set_f32()
            .set_performance_mode(PerformanceMode::LowLatency)
            .set_sharing_mode(SharingMode::Shared)
            .set_input_preset(InputPreset::Unprocessed)
            .set_callback(callback)
            .open_stream()
            .map_err(|e| anyhow::anyhow!("Failed to open Oboe input stream: {:?}", e))?;

        let actual_rate = stream.get_sample_rate() as u32;
        tracing::info!("Oboe capture: opened at {}Hz", actual_rate);

        stream
            .start()
            .map_err(|e| anyhow::anyhow!("Failed to start Oboe input: {:?}", e))?;

        Ok((
            CaptureStream {
                _stream: stream,
                sample_rate: actual_rate,
                active,
            },
            consumer,
        ))
    }

    impl CaptureStream {
        pub fn sample_rate(&self) -> u32 {
            self.sample_rate
        }
        pub fn pause(&self) -> Result<()> {
            // Oboe input streams don't support pause — stop writing to buffer instead
            self.active.store(false, Ordering::Relaxed);
            Ok(())
        }
        pub fn play(&self) -> Result<()> {
            self.active.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
}

#[cfg(target_os = "android")]
pub mod playback {
    use anyhow::Result;
    use oboe::{
        AudioOutputCallback, AudioOutputStreamSafe, AudioStream, AudioStreamBase,
        AudioStreamBuilder, DataCallbackResult, Mono, PerformanceMode, SharingMode,
        Usage, ContentType,
    };
    use ringbuf::traits::{Consumer, Split};
    use ringbuf::HeapRb;

    const TARGET_SAMPLE_RATE: u32 = 48_000;
    const PLAYBACK_BUFFER_SIZE: usize = 48_000 / 5; // ~200ms

    struct OboePlayback {
        consumer: ringbuf::HeapCons<f32>,
        last_samples: [f32; 32],
    }

    impl AudioOutputCallback for OboePlayback {
        type FrameType = (f32, Mono);

        fn on_audio_ready(
            &mut self,
            _stream: &mut dyn AudioOutputStreamSafe,
            audio_data: &mut [f32],
        ) -> DataCallbackResult {
            let read = self.consumer.pop_slice(audio_data);
            if read < audio_data.len() {
                // Underrun: fade out last samples to avoid clicks, then silence
                let fade_len = read.min(32);
                for i in 0..fade_len {
                    let factor = 1.0 - (i as f32 / fade_len as f32);
                    audio_data[read - fade_len + i] *= factor;
                }
                for sample in &mut audio_data[read..] {
                    *sample = 0.0;
                }
            }
            // Store last samples for potential fade-out
            let start = if read >= 32 { read - 32 } else { 0 };
            let count = read.min(32);
            self.last_samples[..count].copy_from_slice(&audio_data[start..start + count]);
            DataCallbackResult::Continue
        }

        fn on_error_after_close(
            &mut self,
            _stream: &mut dyn AudioOutputStreamSafe,
            error: oboe::Error,
        ) {
            tracing::error!("Oboe output stream error: {:?}", error);
        }
    }

    pub struct PlaybackStream {
        _stream: oboe::AudioStreamAsync<oboe::Output, OboePlayback>,
        sample_rate: u32,
    }

    // SAFETY: The Oboe stream is managed internally and the callback uses
    // lock-free ring buffers. PlaybackStream is only used from the main thread.
    unsafe impl Send for PlaybackStream {}
    unsafe impl Sync for PlaybackStream {}

    pub fn start_playback(
        _device_name: Option<&str>,
    ) -> Result<(PlaybackStream, ringbuf::HeapProd<f32>)> {
        let rb = HeapRb::<f32>::new(PLAYBACK_BUFFER_SIZE);
        let (producer, consumer) = rb.split();

        let callback = OboePlayback {
            consumer,
            last_samples: [0.0; 32],
        };

        let mut stream = AudioStreamBuilder::default()
            .set_output()
            .set_sample_rate(TARGET_SAMPLE_RATE as i32)
            .set_mono()
            .set_f32()
            .set_performance_mode(PerformanceMode::LowLatency)
            .set_sharing_mode(SharingMode::Shared)
            .set_usage(Usage::VoiceCommunication)
            .set_content_type(ContentType::Speech)
            .set_callback(callback)
            .open_stream()
            .map_err(|e| anyhow::anyhow!("Failed to open Oboe output stream: {:?}", e))?;

        let actual_rate = stream.get_sample_rate() as u32;
        tracing::info!("Oboe playback: opened at {}Hz", actual_rate);

        stream
            .start()
            .map_err(|e| anyhow::anyhow!("Failed to start Oboe output: {:?}", e))?;

        Ok((
            PlaybackStream {
                _stream: stream,
                sample_rate: actual_rate,
            },
            producer,
        ))
    }

    impl PlaybackStream {
        pub fn sample_rate(&self) -> u32 {
            self.sample_rate
        }
    }
}

#[cfg(target_os = "android")]
pub mod device {
    use anyhow::Result;

    #[derive(Debug, Clone)]
    pub struct AudioDeviceInfo {
        pub name: String,
        pub is_default: bool,
    }

    // Android handles audio routing automatically — expose default devices only
    pub fn list_input_devices() -> Result<Vec<AudioDeviceInfo>> {
        Ok(vec![AudioDeviceInfo {
            name: "Default Microphone".into(),
            is_default: true,
        }])
    }

    pub fn list_output_devices() -> Result<Vec<AudioDeviceInfo>> {
        Ok(vec![AudioDeviceInfo {
            name: "Default Speaker".into(),
            is_default: true,
        }])
    }
}
