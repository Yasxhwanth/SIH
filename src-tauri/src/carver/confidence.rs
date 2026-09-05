// carver/confidence.rs — Confidence scoring model

use serde::{Deserialize, Serialize};

/// Compute a confidence score for a carved file.
///
/// # Parameters
/// - `base`         : signature-defined base score (0.70–0.99)
/// - `has_footer`   : matching footer marker found
/// - `structure_ok` : per-type structural validator passed
/// - `truncated`    : file was cut off at max_size boundary → likely fragment
/// - `overlaps`     : byte region overlaps with another carved file → FP risk
pub fn compute_confidence(
    base: f32,
    has_footer: bool,
    structure_ok: bool,
    truncated: bool,
    overlaps: bool,
) -> f32 {
    let mut score = base;
    if has_footer    { score += 0.05; }
    if structure_ok  { score += 0.05; }
    if truncated     { score -= 0.15; }
    if overlaps      { score -= 0.10; }
    score.clamp(0.0, 1.0)
}

/// Human-readable confidence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLabel {
    High,     // ≥ 0.85
    Medium,   // 0.60 – 0.84
    Low,      // 0.40 – 0.59
    Fragment, // < 0.40 (partial data only)
}

impl From<f32> for ConfidenceLabel {
    fn from(score: f32) -> Self {
        match score {
            s if s >= 0.85 => Self::High,
            s if s >= 0.60 => Self::Medium,
            s if s >= 0.40 => Self::Low,
            _              => Self::Fragment,
        }
    }
}

impl std::fmt::Display for ConfidenceLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High     => write!(f, "High"),
            Self::Medium   => write!(f, "Medium"),
            Self::Low      => write!(f, "Low"),
            Self::Fragment => write!(f, "Fragment"),
        }
    }
}

impl ConfidenceLabel {
    #[allow(dead_code)]
    pub fn css_class(&self) -> &'static str {
        match self {
            Self::High     => "badge-high",
            Self::Medium   => "badge-medium",
            Self::Low      => "badge-low",
            Self::Fragment => "badge-fragment",
        }
    }
}
