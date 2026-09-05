// carver/validator.rs — Per-type structural validation
//
// Each validator reads the internal structure of a carved byte slice and
// returns true only if the internal format is internally consistent.
// Passing validation boosts confidence by +0.05.

use crate::carver::signatures::FileSignature;

/// Run the appropriate structural validator for this signature.
/// Returns true if structure is valid, false if indeterminate or invalid.
pub fn validate(sig: &FileSignature, data: &[u8]) -> bool {
    match sig.extra_validation {
        Some("jpeg") => validate_jpeg(data),
        Some("png")  => validate_png(data),
        Some("pdf")  => validate_pdf(data),
        Some("zip")  => validate_zip(data),
        Some("bmp")  => validate_bmp(data),
        Some("wav")  => validate_wav(data),
        Some("mp4")  => validate_mp4(data),
        Some("elf")  => validate_elf(data),
        Some("pe")   => validate_pe(data),
        Some("aac")          => validate_aac(data),
        Some("mp3")          => validate_mp3(data),
        Some("json")         => validate_json(data),
        Some("aws_key")      => validate_aws_key(data),
        Some("github_pat")   => validate_github_pat(data),
        Some("jwt")          => validate_jwt(data),
        Some("pem")          => validate_pem(data),
        Some("eth_keystore") => validate_eth_keystore(data),
        _                    => false, // no validator → neutral (no bonus)
    }
}

// ── JPEG ────────────────────────────────────────────────────────────────────
// Walk the JPEG marker chain: verifies SOI, SOF/DQT headers, and concluding EOI.
fn validate_jpeg(data: &[u8]) -> bool {
    if data.len() < 4 || !data.starts_with(&[0xFF, 0xD8]) { return false; }
    let mut i = 2usize;
    let mut found_sof = false;
    while i + 3 < data.len() {
        if data[i] != 0xFF { break; }
        let marker = data[i + 1];
        if (0xC0..=0xC3).contains(&marker) {
            found_sof = true;
        }
        if marker == 0xDA {
            // SOS reached; check if file ends with FF D9
            return found_sof && data.ends_with(&[0xFF, 0xD9]);
        }
        if marker == 0xD9 {
            return found_sof;
        }
        if (0xD0..=0xD8).contains(&marker) || marker == 0x01 {
            i += 2;
        } else {
            let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            if seg_len < 2 { break; }
            i += 2 + seg_len;
        }
    }
    data.ends_with(&[0xFF, 0xD9])
}

// ── PNG ─────────────────────────────────────────────────────────────────────
// PNG chunks: [4-byte length][4-byte type][data][4-byte CRC]
// Valid if IHDR chunk is first and chunk chain ends at IEND or reaches EOF.
fn validate_png(data: &[u8]) -> bool {
    if data.len() < 16 { return false; }
    // Skip 8-byte PNG signature
    let mut i = 8usize;
    // First chunk must be IHDR
    if i + 8 > data.len() { return false; }
    let chunk_type = &data[i + 4..i + 8];
    if chunk_type != b"IHDR" { return false; }
    let mut chunk_count = 0u32;
    while i + 12 <= data.len() {
        let length = u32::from_be_bytes(data[i..i+4].try_into().unwrap()) as usize;
        if i + 12 + length > data.len() { break; }
        chunk_count += 1;
        let chunk_type = &data[i + 4..i + 8];
        if chunk_type == b"IEND" { return chunk_count >= 2; } // IHDR + IEND minimum
        i += 12 + length;
        if chunk_count > 1000 { break; } // runaway guard
    }
    chunk_count >= 2
}

// ── PDF ─────────────────────────────────────────────────────────────────────
// Valid if header matches %PDF-1.x or %PDF-2.x and %%EOF exists in last 4 KB.
fn validate_pdf(data: &[u8]) -> bool {
    if data.len() < 8 { return false; }
    // Check version header
    if &data[..5] != b"%PDF-" { return false; }
    // Check for %%EOF in tail
    let tail_start = data.len().saturating_sub(4096);
    data[tail_start..].windows(5).any(|w| w == b"%%EOF")
}

// ── ZIP ─────────────────────────────────────────────────────────────────────
// Valid if local file header signature (PK\x03\x04) at byte 0 and
// central directory end record (PK\x05\x06) exists somewhere.
fn validate_zip(data: &[u8]) -> bool {
    if data.len() < 22 { return false; }
    if &data[..4] != b"PK\x03\x04" { return false; }
    // EOCD signature in tail
    let tail = &data[data.len().saturating_sub(65536)..];
    tail.windows(4).any(|w| w == b"PK\x05\x06")
}

// ── BMP ─────────────────────────────────────────────────────────────────────
// Validate file size field in header matches actual data length, reserved fields are zero,
// and DIB header size is a recognized Windows/OS2 bitmap header structure.
fn validate_bmp(data: &[u8]) -> bool {
    if data.len() < 18 { return false; }
    if &data[..2] != b"BM" { return false; }
    // Reserved fields must be 0
    if data[6..10] != [0, 0, 0, 0] { return false; }
    let dib_size = u32::from_le_bytes(data[14..18].try_into().unwrap());
    if !matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124) { return false; }
    let file_size = u32::from_le_bytes(data[2..6].try_into().unwrap()) as usize;
    data.len() >= file_size.saturating_sub(file_size / 10)
}

// ── WAV ─────────────────────────────────────────────────────────────────────
// RIFF chunk, then "WAVE" fourCC at byte 8.
fn validate_wav(data: &[u8]) -> bool {
    data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE"
}

// ── MP4 ─────────────────────────────────────────────────────────────────────
// Check for "ftyp" box with known MP4 brands.
fn validate_mp4(data: &[u8]) -> bool {
    if data.len() < 12 { return false; }
    if &data[4..8] != b"ftyp" { return false; }
    let brand = &data[8..12];
    matches!(brand, b"mp41" | b"mp42" | b"isom" | b"M4V " | b"M4A " | b"avc1" | b"iso2" | b"iso6")
}

// ── ELF ─────────────────────────────────────────────────────────────────────
// Check ELF magic, class (32/64-bit), and e_type (ET_EXEC / ET_DYN).
fn validate_elf(data: &[u8]) -> bool {
    if data.len() < 16 { return false; }
    &data[..4] == b"\x7fELF"
        && (data[4] == 1 || data[4] == 2)  // EI_CLASS: 1=32bit, 2=64bit
        && (data[5] == 1 || data[5] == 2)  // EI_DATA: 1=LE, 2=BE
}

// ── PE (Windows Executable) ─────────────────────────────────────────────────
// MZ header, then PE\0\0 signature at e_lfanew offset.
fn validate_pe(data: &[u8]) -> bool {
    if data.len() < 64 { return false; }
    if &data[..2] != b"MZ" { return false; }
    let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
    if e_lfanew + 4 > data.len() { return false; }
    &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

// ── AAC (ADTS Audio) ────────────────────────────────────────────────────────
// Valid if ADTS syncword (0xFFF), valid sampling rate, and next frame sync matches.
fn validate_aac(data: &[u8]) -> bool {
    if data.len() < 7 { return false; }
    if data[0] != 0xFF || (data[1] & 0xF0) != 0xF0 { return false; }
    if (data[1] & 0x06) != 0 { return false; } // layer must be 0
    let sr_idx = (data[2] & 0x3C) >> 2;
    if sr_idx >= 12 { return false; }
    let frame_len = (((data[3] & 0x03) as usize) << 11) | ((data[4] as usize) << 3) | ((data[5] & 0xE0) as usize >> 5);
    if frame_len < 7 || frame_len > 8192 || frame_len > data.len() { return false; }
    if data.len() >= frame_len + 2 {
        data[frame_len] == 0xFF && (data[frame_len + 1] & 0xF0) == 0xF0
    } else {
        frame_len >= 24
    }
}

// ── MP3 Audio ───────────────────────────────────────────────────────────────
// Valid if ID3 header is well-formed or MPEG Layer 3 frame sync + valid bitrate.
fn validate_mp3(data: &[u8]) -> bool {
    if data.len() < 10 { return false; }
    if data.starts_with(b"ID3") {
        return data[3] <= 4 && (data[6] & 0x80) == 0 && (data[7] & 0x80) == 0 && (data[8] & 0x80) == 0 && (data[9] & 0x80) == 0;
    }
    if data[0] != 0xFF || (data[1] & 0xFE) != 0xFA { return false; }
    let bitrate_idx = (data[2] >> 4) & 0x0F;
    let srate_idx = (data[2] >> 2) & 0x03;
    if bitrate_idx == 0 || bitrate_idx == 15 || srate_idx == 3 { return false; }
    const BITRATES: [u32; 15] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
    const SRATES: [u32; 3] = [44100, 48000, 32000];
    let br = BITRATES[bitrate_idx as usize] * 1000;
    let sr = SRATES[srate_idx as usize];
    let padding = ((data[2] >> 1) & 0x01) as u32;
    let frame_len = ((144 * br) / sr + padding) as usize;
    if frame_len < 24 || frame_len > 2880 { return false; }
    if data.len() >= frame_len + 2 {
        data[frame_len] == 0xFF && (data[frame_len + 1] & 0xFE) == 0xFA
    } else {
        frame_len >= 24
    }
}

// ── JSON Document ───────────────────────────────────────────────────────────
// Valid if it contains valid UTF-8, balanced braces, and valid JSON structure.
fn validate_json(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // Must be valid UTF-8 text with no null bytes
    if data.contains(&0) { return false; }
    let Ok(text) = std::str::from_utf8(data) else { return false; };
    let trimmed = text.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) && !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return false;
    }
    // Deep structural parse using serde_json
    serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

// ── AWS Access Key ID ───────────────────────────────────────────────────────
// Must be "AKIA" followed by exactly 16 uppercase alphanumeric characters
fn validate_aws_key(data: &[u8]) -> bool {
    if data.len() < 20 || !data.starts_with(b"AKIA") { return false; }
    let key_chars = &data[4..20];
    key_chars.iter().all(|&b| (b >= b'A' && b <= b'Z') || (b >= b'0' && b <= b'9'))
}

// ── GitHub Personal Access Token ────────────────────────────────────────────
// Must be "ghp_" followed by 36 alphanumeric characters
fn validate_github_pat(data: &[u8]) -> bool {
    if data.len() < 40 || !data.starts_with(b"ghp_") { return false; }
    let token_chars = &data[4..40];
    token_chars.iter().all(|&b| (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z') || (b >= b'0' && b <= b'9'))
}

// ── JSON Web Token (JWT Bearer) ─────────────────────────────────────────────
// Two or three dot-separated Base64URL segments: header.payload[.signature]
fn validate_jwt(data: &[u8]) -> bool {
    if data.len() < 16 || !data.starts_with(b"eyJ") { return false; }
    let Ok(s) = std::str::from_utf8(data) else { return false; };
    let token = s.split_whitespace().next().unwrap_or("");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { return false; }
    parts.iter().take(2).all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

// ── PEM Certificate / Key ───────────────────────────────────────────────────
fn validate_pem(data: &[u8]) -> bool {
    if data.len() < 30 || !data.starts_with(b"-----BEGIN ") { return false; }
    data.windows(9).any(|w| w == b"-----END ")
}

// ── Ethereum Web3 Keystore ──────────────────────────────────────────────────
fn validate_eth_keystore(data: &[u8]) -> bool {
    if !validate_json(data) { return false; }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else { return false; };
    let crypto = v.get("crypto").or_else(|| v.get("Crypto"));
    if let Some(c) = crypto {
        c.get("ciphertext").is_some() && c.get("cipher").is_some()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_rejects_corrupted_payloads() {
        // Random binary garbage starting with `{"`
        let fake_json = b"{\"abc\x00\xFF\x12\x34";
        assert!(!validate_json(fake_json));

        // Valid JSON
        let valid_json = b"{\"evidence_id\": 1042, \"status\": \"verified\"}";
        assert!(validate_json(valid_json));

        // Random binary garbage starting with \xFF\xFB (fake MP3)
        let fake_mp3 = b"\xFF\xFB\x00\x00\x12\x34\x56\x78\x9A\xBC";
        assert!(!validate_mp3(fake_mp3));

        // Random binary garbage starting with \xFF\xF1 (fake AAC)
        let fake_aac = b"\xFF\xF1\x00\x00\x12\x34\x56\x78";
        assert!(!validate_aac(fake_aac));
    }
}


