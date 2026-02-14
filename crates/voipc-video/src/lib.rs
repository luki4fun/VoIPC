pub mod encoder;
pub mod decoder;
pub mod convert;

/// Screen share resolution presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// 854x480
    P480,
    /// 1280x720
    P720,
    /// 1920x1080
    P1080,
}

impl Resolution {
    pub fn width(self) -> u32 {
        match self {
            Resolution::P480 => 854,
            Resolution::P720 => 1280,
            Resolution::P1080 => 1920,
        }
    }

    pub fn height(self) -> u32 {
        match self {
            Resolution::P480 => 480,
            Resolution::P720 => 720,
            Resolution::P1080 => 1080,
        }
    }

    /// Target bitrate in kilobits per second.
    pub fn bitrate_kbps(self) -> u32 {
        match self {
            Resolution::P480 => 1500,
            Resolution::P720 => 3000,
            Resolution::P1080 => 5000,
        }
    }

    /// Target frames per second.
    pub fn target_fps(self) -> u32 {
        match self {
            Resolution::P480 => 30,
            Resolution::P720 => 30,
            Resolution::P1080 => 30,
        }
    }

    pub fn from_height(h: u16) -> Option<Self> {
        match h {
            480 => Some(Resolution::P480),
            720 => Some(Resolution::P720),
            1080 => Some(Resolution::P1080),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_from_height_all_valid() {
        assert_eq!(Resolution::from_height(480), Some(Resolution::P480));
        assert_eq!(Resolution::from_height(720), Some(Resolution::P720));
        assert_eq!(Resolution::from_height(1080), Some(Resolution::P1080));
    }

    #[test]
    fn resolution_from_height_invalid() {
        assert_eq!(Resolution::from_height(0), None);
        assert_eq!(Resolution::from_height(360), None);
        assert_eq!(Resolution::from_height(1440), None);
    }

    #[test]
    fn resolution_dimensions() {
        assert_eq!((Resolution::P480.width(), Resolution::P480.height()), (854, 480));
        assert_eq!((Resolution::P720.width(), Resolution::P720.height()), (1280, 720));
        assert_eq!((Resolution::P1080.width(), Resolution::P1080.height()), (1920, 1080));
    }

    #[test]
    fn resolution_bitrate() {
        assert_eq!(Resolution::P480.bitrate_kbps(), 1500);
        assert_eq!(Resolution::P720.bitrate_kbps(), 3000);
        assert_eq!(Resolution::P1080.bitrate_kbps(), 5000);
    }

    #[test]
    fn resolution_fps() {
        assert_eq!(Resolution::P480.target_fps(), 30);
        assert_eq!(Resolution::P720.target_fps(), 30);
        assert_eq!(Resolution::P1080.target_fps(), 30);
    }

    #[test]
    fn resolution_equality() {
        assert_eq!(Resolution::P720, Resolution::P720);
        assert_ne!(Resolution::P720, Resolution::P480);
    }
}
