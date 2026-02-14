use voipc_protocol::voice::OPUS_FRAME_SIZE;

/// Mixes multiple decoded audio streams into a single output buffer.
///
/// Each input is a slice of `OPUS_FRAME_SIZE` f32 samples from a different user.
/// Output is the sum of all inputs, clamped to [-1.0, 1.0].
pub fn mix_streams(streams: &[&[f32]]) -> Vec<f32> {
    let mut output = vec![0.0f32; OPUS_FRAME_SIZE];

    for stream in streams {
        let len = stream.len().min(OPUS_FRAME_SIZE);
        for i in 0..len {
            output[i] += stream[i];
        }
    }

    // Clamp to prevent distortion
    for sample in &mut output {
        *sample = sample.clamp(-1.0, 1.0);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_two_streams() {
        let a = vec![0.5f32; OPUS_FRAME_SIZE];
        let b = vec![0.3f32; OPUS_FRAME_SIZE];

        let mixed = mix_streams(&[&a, &b]);
        assert!((mixed[0] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn mix_clamps() {
        let a = vec![0.8f32; OPUS_FRAME_SIZE];
        let b = vec![0.8f32; OPUS_FRAME_SIZE];

        let mixed = mix_streams(&[&a, &b]);
        assert_eq!(mixed[0], 1.0); // clamped
    }

    #[test]
    fn mix_empty() {
        let mixed = mix_streams(&[]);
        assert_eq!(mixed.len(), OPUS_FRAME_SIZE);
        assert_eq!(mixed[0], 0.0);
    }

    #[test]
    fn mix_single_stream() {
        let a = vec![0.5f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams(&[&a]);
        assert!((mixed[0] - 0.5).abs() < 1e-6);
        assert!((mixed[OPUS_FRAME_SIZE - 1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn mix_many_streams() {
        let streams: Vec<Vec<f32>> = (0..10).map(|_| vec![0.1f32; OPUS_FRAME_SIZE]).collect();
        let refs: Vec<&[f32]> = streams.iter().map(|s| s.as_slice()).collect();
        let mixed = mix_streams(&refs);
        assert!((mixed[0] - 1.0).abs() < 1e-5);
    }

    #[test]
    fn mix_negative_clamps() {
        let a = vec![-0.8f32; OPUS_FRAME_SIZE];
        let b = vec![-0.8f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams(&[&a, &b]);
        assert_eq!(mixed[0], -1.0); // clamped to -1.0
    }

    #[test]
    fn mix_output_length() {
        let a = vec![0.1f32; 100]; // shorter than OPUS_FRAME_SIZE
        let mixed = mix_streams(&[&a]);
        assert_eq!(mixed.len(), OPUS_FRAME_SIZE);
    }
}
