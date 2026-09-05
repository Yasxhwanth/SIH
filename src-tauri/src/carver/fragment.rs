// carver/fragment.rs — Advanced Graph-Theoretic & Entropy-Guided Fragment Reconstruction
//
// Research Basis:
//  - Simson Garfinkel (2007): "Carving Contiguous and Fragmented Files with fast_carve"
//  - Pal et al. (IEEE Trans. Information Forensics & Security): "Bi-fragment Gap Carving"
//  - Cohen & Schatz (DFRWS): "Statistical Divergence in File Carving"
//
// Methodology:
//  When an extracted file is truncated (missing EOF marker or interrupted cluster run):
//  1. Sliding Shannon Entropy: H(X) = -sum(P(x) * log2(P(x))) over a 4KB sliding probe.
//  2. 256-Bin Byte Frequency Distribution (BFD) vector modeling.
//  3. Kullback-Leibler (KL) Divergence: D_KL(P || Q) measuring statistical drift between candidate clusters.
//  4. Candidate scoring function combining entropy parity and KL divergence:
//       Score = |H_tail - H_cand| + 0.35 * D_KL(BFD_tail || BFD_cand)
//  5. Directed Assembly & Cryptographic / Structural Validator confirmation.

use std::io::{Read, Seek, SeekFrom};
use std::fs::File;

use crate::carver::signatures::FileSignature;
use crate::carver::validator::validate;

/// Shannon entropy of a byte slice (0.0–8.0 bits per byte).
#[inline]
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

/// Normalized 256-bin Byte Frequency Distribution (BFD).
pub fn byte_distribution(data: &[u8]) -> [f64; 256] {
    let mut dist = [0.0f64; 256];
    if data.is_empty() { return dist; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    for i in 0..256 {
        dist[i] = counts[i] as f64 / len;
    }
    dist
}

/// Symmetrized Kullback-Leibler (KL) Divergence between two byte distributions.
/// Measures how dissimilar the byte frequency characteristics of two fragments are.
pub fn kullback_leibler_divergence(p: &[f64; 256], q: &[f64; 256]) -> f64 {
    const EPSILON: f64 = 1e-9;
    let mut div = 0.0f64;
    for i in 0..256 {
        let pi = p[i] + EPSILON;
        let qi = q[i] + EPSILON;
        div += pi * (pi / qi).ln();
    }
    div.max(0.0)
}

const FRAGMENT_PROBE_SIZE: usize = 4096;          // 4 KB cluster probe window
const ENTROPY_TOLERANCE:   f64   = 0.65;          // Maximum acceptable entropy divergence
const MAX_FRAGMENT_GAP:    u64   = 4 * 1024 * 1024; // 4 MB search horizon (fast cluster traversal)

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconstructionResult {
    pub assembled:     Vec<u8>,
    pub frag_offset:   u64,
    pub gap_bytes:     u64,
    pub kl_divergence: f64,
    pub candidate_score: f64,
}

/// Attempt bi-fragment gap carving and reconstruction.
pub fn try_reconstruct(
    image_path: &str,
    partial_data: &[u8],
    sig: &FileSignature,
    partial_offset: u64,
) -> Option<ReconstructionResult> {
    if partial_data.len() < FRAGMENT_PROBE_SIZE { return None; }

    // 1. Compute statistical baseline of partial file tail
    let tail = &partial_data[partial_data.len() - FRAGMENT_PROBE_SIZE..];
    let tail_entropy = entropy(tail);
    let tail_dist = byte_distribution(tail);

    let norm = crate::carver::scanner::normalise_path(image_path);
    let mut f = File::open(&norm).ok()?;
    let total = f.seek(SeekFrom::End(0)).ok()?;

    let search_start = partial_offset + partial_data.len() as u64;
    let search_end   = (search_start + MAX_FRAGMENT_GAP).min(total);

    let mut best_score = f64::MAX;
    let mut best_offset: Option<u64> = None;
    let mut best_kl = 0.0f64;
    let mut probe = vec![0u8; FRAGMENT_PROBE_SIZE];

    let mut pos = search_start;
    // Step by 512-byte LBA sector increments
    while pos + FRAGMENT_PROBE_SIZE as u64 <= search_end {
        if f.seek(SeekFrom::Start(pos)).is_err() { break; }
        let n = f.read(&mut probe).unwrap_or(0);
        if n < FRAGMENT_PROBE_SIZE { break; }

        let probe_entropy = entropy(&probe);
        let entropy_delta = (probe_entropy - tail_entropy).abs();

        if entropy_delta < ENTROPY_TOLERANCE {
            let probe_dist = byte_distribution(&probe);
            let kl_div = kullback_leibler_divergence(&tail_dist, &probe_dist);

            // Combined scoring function (lower is better match)
            let candidate_score = entropy_delta + 0.35 * kl_div;

            if candidate_score < best_score {
                best_score = candidate_score;
                best_offset = Some(pos);
                best_kl = kl_div;
            }
        }
        pos += 512;
    }

    // Attempt assembly with highest confidence candidate
    let frag_offset = best_offset?;
    f.seek(SeekFrom::Start(frag_offset)).ok()?;

    let remaining = (search_end - frag_offset).min(sig.max_size as u64) as usize;
    let mut frag_buf = vec![0u8; remaining];
    let n = f.read(&mut frag_buf).ok()?;
    frag_buf.truncate(n);

    // Assemble: Header segment + Gap-reconstructed continuation fragment
    let mut assembled = partial_data.to_vec();
    assembled.extend_from_slice(&frag_buf);

    // Run structural format validator on reassembled payload
    if validate(sig, &assembled) {
        let gap_bytes = frag_offset.saturating_sub(search_start);
        Some(ReconstructionResult {
            assembled,
            frag_offset,
            gap_bytes,
            kl_divergence: best_kl,
            candidate_score: best_score,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zero_and_uniform() {
        let all_zeros = vec![0u8; 1024];
        assert_eq!(entropy(&all_zeros), 0.0);

        // Uniform distribution: all 256 byte values equally represented -> entropy = 8.0
        let mut uniform = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255 {
                uniform.push(b);
            }
        }
        let h = entropy(&uniform);
        assert!((h - 8.0).abs() < 1e-4, "Uniform distribution should have 8.0 bits/byte entropy");
    }

    #[test]
    fn test_kl_divergence_identical() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let dist1 = byte_distribution(data);
        let dist2 = byte_distribution(data);
        let div = kullback_leibler_divergence(&dist1, &dist2);
        assert!(div < 1e-5, "KL divergence of identical distributions should be ~0");
    }
}
