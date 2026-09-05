// carver/scanner.rs — High-performance parallel byte scanner
//
// Two execution paths depending on source type:
//
//  ┌─ Regular file ─────────────────────────────────────────────────────────┐
//  │  memmap2::Mmap  →  rayon parallel chunk scan                           │
//  │  • Zero-copy: OS page cache handles I/O                                │
//  │  • One task per rayon thread, each scanning a 32 MB region             │
//  │  • Chunks overlap by CHUNK_OVERLAP bytes so magic bytes                │
//  │    crossing a boundary are never missed                                │
//  └────────────────────────────────────────────────────────────────────────┘
//  ┌─ Raw block device (\\.\E:, /dev/sdX) ──────────────────────────────────┐
//  │  16 MB double-buffered async I/O pipeline + rayon window parallelism   │
//  │  • Background reader pre-fetches contiguous 16 MB chunks via channel   │
//  │  • Zero memory allocations in loop (recycling buffer pool)             │
//  │  • FILE_FLAG_SEQUENTIAL_SCAN kernel prefetch hint on Windows           │
//  │  • Zero-run SIMD word-skip leaps past empty sectors at RAM bus speed   │
//  └────────────────────────────────────────────────────────────────────────┘

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::collections::HashSet;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use rayon::prelude::*;
use memmap2::Mmap;

use crate::carver::signatures::{FileSignature, build_index};

// ── Tuning constants ──────────────────────────────────────────────────────────

pub const SECTOR_SIZE:     usize = 512;

/// Size of each parallel work chunk (mmap path)
const CHUNK_SIZE:          usize = 16 * 1024 * 1024;   // 16 MB

/// Overlap between adjacent chunks — aligned to physical sector size (512 bytes)
pub const CHUNK_OVERLAP:   usize = 512;

/// Read-buffer size for block devices (device path, double-buffered async I/O)
pub const DEVICE_BUF:      usize = 32 * 1024 * 1024;   // 32 MB — larger sequential reads amortize USB/SATA latency

// ── Public types ──────────────────────────────────────────────────────────────

/// A confirmed magic-byte match at a raw byte offset in the image.
#[derive(Debug, Clone)]
pub struct HitEvent {
    pub offset:  u64,
    pub sig_idx: usize,
}

/// Progress callback: (bytes_scanned, total_bytes)
pub type ProgressFn = Box<dyn Fn(u64, u64) + Send + Sync + 'static>;

/// Streaming hit callback: invoked immediately in real time when a file signature matches.
pub type HitFn = Arc<dyn Fn(HitEvent) + Send + Sync>;

// ── Path normalisation (Windows drive letter → raw device path) ───────────────

/// Normalise a user-supplied path for Windows raw device I/O.
///
/// | Input                | Output           |
/// |----------------------|------------------|
/// | `E:`  /  `E:\`      | `\\.\E:`         |
/// | `\\.\E:`             | unchanged        |
/// | `\\.\PhysicalDrive2` | unchanged        |
/// | `/path/to/img`       | unchanged        |
pub fn normalise_path(path: &str) -> String {
    let p = path.trim();
    if p.starts_with(r"\\.\") || p.starts_with(r"//./") {
        return p.to_string();
    }
    let b = p.as_bytes();
    // Only convert if it's strictly a drive root (e.g. "E:", "E:\", "E:/")
    if (b.len() == 2 || (b.len() == 3 && (b[2] == b'\\' || b[2] == b'/')))
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
    {
        return format!(r"\\.\{}:", b[0].to_ascii_uppercase() as char);
    }
    p.to_string()
}

// ── Windows device-size IOCTL ─────────────────────────────────────────────────

#[cfg(windows)]
fn query_device_size(handle: *mut winapi::ctypes::c_void) -> Option<u64> {
    use std::mem;
    use winapi::um::ioapiset::DeviceIoControl;
    use winapi::um::winioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DISK_GEOMETRY_EX};

    // 1. Primary volume & disk size query: IOCTL_DISK_GET_LENGTH_INFO (0x0007405C)
    // Works reliably on both partition volume handles (\\.\D:, \\.\E:) and physical disks (\\.\PhysicalDrive0)
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;
    #[repr(C)]
    struct GetLengthInformation {
        length: i64,
    }
    let mut len_info: GetLengthInformation = unsafe { mem::zeroed() };
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null_mut(), 0,
            &mut len_info as *mut _ as *mut _,
            mem::size_of::<GetLengthInformation>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 && len_info.length > 0 {
        return Some(len_info.length as u64);
    }

    // 2. Secondary physical disk geometry query
    let mut geo: DISK_GEOMETRY_EX = unsafe { mem::zeroed() };
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            std::ptr::null_mut(), 0,
            &mut geo as *mut _ as *mut _,
            mem::size_of::<DISK_GEOMETRY_EX>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 && returned >= 8 {
        let size_ptr = unsafe {
            let base = &geo as *const DISK_GEOMETRY_EX as *const u8;
            base.add(24) as *const i64   // DiskSize follows DISK_GEOMETRY (24 bytes)
        };
        let size = unsafe { *size_ptr };
        if size > 0 { return Some(size as u64); }
    }
    None
}

#[cfg(not(windows))]
fn query_device_size(_: i32) -> Option<u64> { None }

// ── Helpers ───────────────────────────────────────────────────────────────────

fn open_source(norm: &str) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        // FILE_FLAG_SEQUENTIAL_SCAN (0x0800_0000): hints Windows Cache Manager to prefetch sequential blocks.
        // FILE_FLAG_NO_BUFFERING  (0x2000_0000): bypasses Windows disk cache for raw device reads — prevents
        // double-buffering and is the technique used by FTK Imager / Disk Drill for maximum forensic throughput.
        // NOTE: NO_BUFFERING requires all reads to start on and be multiples of the physical sector size (512 B).
        // Our CHUNK_OVERLAP + DEVICE_BUF buffer pre-allocation already satisfies this constraint.
        let flags = if norm.starts_with(r"\\.\") || norm.starts_with(r"//./") {
            0x0800_0000 | 0x2000_0000  // Raw volume: SEQUENTIAL_SCAN + NO_BUFFERING
        } else {
            0x0800_0000                // Regular file: SEQUENTIAL_SCAN only
        };
        opts.custom_flags(flags);
    }
    opts.open(norm)
}

fn get_total_size(f: &File, norm: &str) -> u64 {
    // Is it a regular file?
    if let Ok(meta) = f.metadata() {
        if meta.is_file() && meta.len() > 0 {
            return meta.len();
        }
    }
    // Block device — try IOCTL on Windows, else seek-to-end
    #[cfg(windows)]
    {
        let h = f.as_raw_handle();
        if let Some(sz) = query_device_size(h as _) {
            return sz;
        }
    }
    // Fallback: seek-to-end (works on Linux block devices)
    if let Ok(mut f2) = open_source(norm) {
        if let Ok(sz) = f2.seek(SeekFrom::End(0)) {
            if sz > 0 { return sz; }
        }
    }
    0
}

fn is_mappable(f: &File) -> bool {
    f.metadata().map(|m| m.is_file()).unwrap_or(false)
}

// ── Fast candidate filter & inner scan ───────────────────────────────────────

/// Precompute a fast boolean bitmap for whether a byte begins any file signature.
/// Fits entirely into L1 cache for instant O(1) branch prediction.
pub fn build_candidate_filter(index: &[Vec<usize>; 256]) -> [bool; 256] {
    let mut hc = [false; 256];
    for (b, list) in index.iter().enumerate() {
        if !list.is_empty() {
            hc[b] = true;
        }
    }
    hc
}

/// Fast in-stream secondary header verification for short signatures (<= 4 bytes)
/// to eliminate false positives from random byte sequences.
#[inline]
fn verify_secondary_header(data: &[u8], offset: usize, sig: &FileSignature) -> bool {
    let remaining = data.len().saturating_sub(offset);
    match sig.extension {
        "bmp" => {
            if remaining < 18 { return false; }
            let slice = &data[offset..];
            // Reserved1 and Reserved2 must be 0
            if slice[6..10] != [0, 0, 0, 0] { return false; }
            let dib_size = u32::from_le_bytes(slice[14..18].try_into().unwrap());
            // Valid DIB sizes: 12 (CORE), 40 (INFO), 52 (V2), 56 (V3), 64 (OS2), 108 (V4), 124 (V5)
            if !matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124) { return false; }
            let file_size = u32::from_le_bytes(slice[2..6].try_into().unwrap());
            file_size >= 54 && file_size <= 200 * 1024 * 1024
        }
        "exe" => {
            if remaining < 64 { return false; }
            let slice = &data[offset..];
            let e_lfanew = u32::from_le_bytes(slice[60..64].try_into().unwrap()) as usize;
            if e_lfanew < 64 || e_lfanew > 1024 || offset + e_lfanew + 4 > data.len() {
                return false;
            }
            &data[offset + e_lfanew..offset + e_lfanew + 4] == b"PE\0\0"
        }
        "wav" => {
            if remaining < 12 { return false; }
            &data[offset + 8..offset + 12] == b"WAVE"
        }
        "webp" => {
            if remaining < 12 { return false; }
            &data[offset + 8..offset + 12] == b"WEBP"
        }
        "ico" => {
            if remaining < 6 { return false; }
            let slice = &data[offset..];
            slice[2..4] == [1, 0] && slice[4] > 0
        }
        "aac" => {
            if remaining < 7 { return false; }
            let slice = &data[offset..];
            if slice[0] != 0xFF || (slice[1] & 0xF0) != 0xF0 || (slice[1] & 0x06) != 0 { return false; }
            let sr_idx = (slice[2] & 0x3C) >> 2;
            if sr_idx >= 12 { return false; }
            let frame_len = (((slice[3] & 0x03) as usize) << 11) | ((slice[4] as usize) << 3) | ((slice[5] & 0xE0) as usize >> 5);
            if frame_len < 7 || frame_len > 8192 { return false; }
            if remaining >= frame_len + 2 {
                slice[frame_len] == 0xFF && (slice[frame_len + 1] & 0xF0) == 0xF0
            } else {
                true
            }
        }
        "mp3" => {
            if sig.magic == b"ID3" {
                if remaining < 10 { return false; }
                let slice = &data[offset..];
                slice[3] <= 4 && (slice[6] & 0x80) == 0 && (slice[7] & 0x80) == 0 && (slice[8] & 0x80) == 0 && (slice[9] & 0x80) == 0
            } else {
                if remaining < 4 { return false; }
                let slice = &data[offset..];
                if slice[0] != 0xFF || (slice[1] & 0xFE) != 0xFA { return false; }
                let bitrate_idx = (slice[2] >> 4) & 0x0F;
                let srate_idx = (slice[2] >> 2) & 0x03;
                if bitrate_idx == 0 || bitrate_idx == 15 || srate_idx == 3 { return false; }
                true
            }
        }
        "json" => {
            if remaining < 6 { return false; }
            let slice = &data[offset..];
            let mut j = 2;
            while j < slice.len().min(48) && slice[j] != b'"' {
                if slice[j] < 0x20 || slice[j] == 0x7F { return false; }
                j += 1;
            }
            if j >= slice.len().min(48) || slice[j] != b'"' { return false; }
            j += 1;
            while j < slice.len().min(56) && (slice[j] == b' ' || slice[j] == b'\t' || slice[j] == b'\r' || slice[j] == b'\n') {
                j += 1;
            }
            j < slice.len() && slice[j] == b':'
        }
        _ => true,
    }
}

/// Scan a byte slice for all signature magic patterns.
/// Returns hits with offsets relative to the start of the full source.
#[inline]
fn scan_slice(
    data:           &[u8],
    base_offset:    u64,
    sigs:           &[FileSignature],
    index:          &[Vec<usize>; 256],
    has_candidates: &[bool; 256],
) -> Vec<HitEvent> {
    let mut hits: Vec<HitEvent> = Vec::new();
    let len = data.len();
    let mut i = 0;

    while i < len {
        let byte = unsafe { *data.get_unchecked(i) };

        // High-speed zero-run skip: unallocated / wiped space is dominated by 0x00 runs.
        // If an entire 8-byte word is 0x00, no registered signature can start here
        // (even 0x00 magics like MP4, HEIC, WASM contain non-zero bytes within the first 4 bytes).
        if byte == 0 && i + 8 <= len {
            let word = unsafe { std::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
            if word == 0 {
                i += 8;
                while i + 8 <= len {
                    let w = unsafe { std::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
                    if w == 0 {
                        i += 8;
                    } else {
                        break;
                    }
                }
                continue;
            }
        }

        // Fast-reject byte values with no registered signatures (~230+ out of 256 byte values)
        if !unsafe { *has_candidates.get_unchecked(byte as usize) } {
            i += 1;
            continue;
        }

        // Potential signature start byte — verify candidates
        let candidates = unsafe { index.get_unchecked(byte as usize) };
        'sig: for &sig_idx in candidates {
            let sig   = &sigs[sig_idx];
            let magic = &sig.magic;
            let end   = i + magic.len();
            if end > len { continue 'sig; }
            if unsafe { data.get_unchecked(i..end) } == magic.as_slice() {
                let hit_off = base_offset + i as u64;

                // Sector alignment constraint for short signatures (<= 2 bytes):
                // In block storage and filesystem images, files always align to sector boundaries.
                // Disallow random mid-sector 2-byte collisions (e.g. `{"`, `BM`, `\xff\xfb`, `\xff\xf1`).
                if sig.magic.len() <= 2 && hit_off % (SECTOR_SIZE as u64) != 0 {
                    continue 'sig;
                }

                // Secondary structural verification on short magics to suppress false positives
                if !verify_secondary_header(data, i, sig) {
                    continue 'sig;
                }

                if hits.last().map_or(true, |h: &HitEvent| {
                    h.offset != hit_off || h.sig_idx != sig_idx
                }) {
                    hits.push(HitEvent { offset: hit_off, sig_idx });
                }
            }
        }
        i += 1;
    }
    hits
}

// ── Path 1: Memory-mapped parallel scan (regular files) ───────────────────────

fn scan_mmap(
    f:           &File,
    total:       u64,
    sigs:        &[FileSignature],
    cancel:      Arc<AtomicBool>,
    on_progress: ProgressFn,
    on_hit:      Option<HitFn>,
) -> std::io::Result<Vec<HitEvent>> {
    let mmap = unsafe { Mmap::map(f)? };
    let data: &[u8] = &mmap;
    let idx_table = build_index(sigs);
    let hc_table = build_candidate_filter(&idx_table);
    let index = Arc::new(idx_table);
    let has_candidates = Arc::new(hc_table);

    // Divide into CHUNK_SIZE chunks for responsive real-time streaming
    let chunk_size = CHUNK_SIZE;
    let mut chunks: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let end = (pos + chunk_size + CHUNK_OVERLAP).min(data.len());
        chunks.push((pos, end));
        if end >= data.len() { break; }
        pos += chunk_size;
    }

    let scanned_bytes = Arc::new(AtomicU64::new(0));
    let on_progress   = Arc::new(on_progress);
    let seen_hits     = Arc::new(Mutex::new(HashSet::<(u64, usize)>::new()));

    let chunk_results: Vec<Vec<HitEvent>> = chunks
        .into_par_iter()
        .map_with((Arc::clone(&index), Arc::clone(&has_candidates), Arc::clone(&cancel), Arc::clone(&scanned_bytes), Arc::clone(&seen_hits)),
            |(idx, hc, cncl, sb, seen), (start, end)| {
                if cncl.load(Ordering::Relaxed) { return vec![]; }
                let slice = &data[start..end];
                let hits  = scan_slice(slice, start as u64, sigs, idx, hc);
                let bytes = (end - start).min(chunk_size) as u64;
                let current_scanned = sb.fetch_add(bytes, Ordering::Relaxed) + bytes;
                on_progress(current_scanned.min(total), total);

                if let Some(ref cb) = on_hit {
                    for hit in &hits {
                        let mut guard = seen.lock().unwrap();
                        if guard.insert((hit.offset, hit.sig_idx)) {
                            cb(hit.clone());
                        }
                    }
                }
                hits
            })
        .collect();

    on_progress(total, total);

    let mut all: Vec<HitEvent> = chunk_results.into_iter().flatten().collect();
    all.sort_by_key(|h| (h.offset, h.sig_idx));
    all.dedup_by(|a, b| a.offset == b.offset && a.sig_idx == b.sig_idx);
    Ok(all)
}

// ── Path 2: Buffered device scan with double-buffered async pipeline ──────────

enum BufferPacket {
    Data {
        buffer:      Vec<u8>,
        valid_len:   usize,
        base_offset: u64,
        bytes_read:  u64,
        is_first:    bool,
    },
    Eof,
    Error(String),
}

fn scan_device(
    norm:        &str,
    total:       u64,
    sigs:        &[FileSignature],
    cancel:      Arc<AtomicBool>,
    on_progress: ProgressFn,
    on_hit:      Option<HitFn>,
) -> std::io::Result<Vec<HitEvent>> {
    let idx_table = build_index(sigs);
    let has_candidates = build_candidate_filter(&idx_table);
    let index = Arc::new(idx_table);
    let hc = Arc::new(has_candidates);

    // Double-buffered channels:
    // to_worker: background reader sends pre-fetched buffers to worker thread
    // recycle: worker returns consumed buffers back to reader for zero-allocation reuse
    let (to_worker_tx, to_worker_rx) = mpsc::sync_channel::<BufferPacket>(2);
    let (recycle_tx, recycle_rx)     = mpsc::sync_channel::<Vec<u8>>(3);

    // Pre-allocate 3 buffers (CHUNK_OVERLAP + DEVICE_BUF)
    let total_buf_len = CHUNK_OVERLAP + DEVICE_BUF;
    for _ in 0..3 {
        let _ = recycle_tx.send(vec![0u8; total_buf_len]);
    }

    let norm_string = norm.to_string();
    let reader_cancel = Arc::clone(&cancel);

    let reader_thread = std::thread::Builder::new()
        .name("forensix-async-reader".into())
        .spawn(move || {
            let mut f = match open_source(&norm_string) {
                Ok(file) => file,
                Err(e) => {
                    let _ = to_worker_tx.send(BufferPacket::Error(e.to_string()));
                    return;
                }
            };

            let mut file_offset: u64 = 0;
            let mut prev_overlap = [0u8; CHUNK_OVERLAP];
            let mut is_first = true;

            while !reader_cancel.load(Ordering::Relaxed) {
                let mut buf = match recycle_rx.recv() {
                    Ok(b) => b,
                    Err(_) => break, // worker closed channel
                };

                if !is_first {
                    buf[..CHUNK_OVERLAP].copy_from_slice(&prev_overlap);
                }

                let target = &mut buf[CHUNK_OVERLAP..CHUNK_OVERLAP + DEVICE_BUF];
                let mut n = 0;
                let mut read_err = None;

                while n < target.len() {
                    match f.read(&mut target[n..]) {
                        Ok(0) => break,
                        Ok(bytes) => n += bytes,
                        Err(e) => {
                            if n > 0 { break; }
                            read_err = Some(e.to_string());
                            break;
                        }
                    }
                }

                if let Some(e) = read_err {
                    let _ = to_worker_tx.send(BufferPacket::Error(e));
                    break;
                }

                if n == 0 {
                    let _ = to_worker_tx.send(BufferPacket::Eof);
                    break;
                }

                if n >= CHUNK_OVERLAP {
                    prev_overlap.copy_from_slice(&target[n - CHUNK_OVERLAP..n]);
                } else {
                    prev_overlap.fill(0);
                    prev_overlap[CHUNK_OVERLAP - n..].copy_from_slice(&target[..n]);
                }

                let valid_len = if is_first { n } else { n + CHUNK_OVERLAP };
                let base_offset = if is_first { 0 } else { file_offset - CHUNK_OVERLAP as u64 };
                let bytes_read = n as u64;

                let packet = BufferPacket::Data {
                    buffer: buf,
                    valid_len,
                    base_offset,
                    bytes_read,
                    is_first,
                };

                is_first = false;
                file_offset += bytes_read;

                if to_worker_tx.send(packet).is_err() {
                    break;
                }
            }
        });

    let mut hits = Vec::<HitEvent>::new();
    let mut scanned_bytes: u64 = 0;
    let seen_hits = Arc::new(Mutex::new(HashSet::<(u64, usize)>::new()));

    while let Ok(packet) = to_worker_rx.recv() {
        if cancel.load(Ordering::Relaxed) { break; }

        match packet {
            BufferPacket::Error(e) => {
                log::warn!("Device read error during carving scan: {}", e);
                break;
            }
            BufferPacket::Eof => break,
            BufferPacket::Data { buffer, valid_len, base_offset, bytes_read, is_first } => {
                let window: &[u8] = if is_first {
                    &buffer[CHUNK_OVERLAP..CHUNK_OVERLAP + valid_len]
                } else {
                    &buffer[..valid_len]
                };

                // Split into parallel Rayon ranges with CHUNK_OVERLAP safety boundary
                let num_threads = rayon::current_num_threads().max(1);
                let base_chunk = (window.len() / num_threads).max(1024 * 1024);

                let mut sub_ranges = Vec::new();
                let mut pos = 0usize;
                while pos < window.len() {
                    let end = (pos + base_chunk + CHUNK_OVERLAP).min(window.len());
                    sub_ranges.push((pos, end));
                    if end >= window.len() { break; }
                    pos += base_chunk;
                }

                let sub_hits: Vec<HitEvent> = sub_ranges
                    .into_par_iter()
                    .map_with((Arc::clone(&index), Arc::clone(&hc), Arc::clone(&cancel)),
                        |(idx, hc_ref, cncl), (start, end)| {
                            if cncl.load(Ordering::Relaxed) { return vec![]; }
                            let slice = &window[start..end];
                            let chunk_base = base_offset + start as u64;
                            scan_slice(slice, chunk_base, sigs, idx, hc_ref)
                        })
                    .flatten()
                    .collect();

                if let Some(ref cb) = on_hit {
                    for hit in &sub_hits {
                        let mut guard = seen_hits.lock().unwrap();
                        if guard.insert((hit.offset, hit.sig_idx)) {
                            cb(hit.clone());
                        }
                    }
                }

                hits.extend(sub_hits);

                scanned_bytes += bytes_read;
                on_progress(scanned_bytes.min(total), total);

                // Return buffer to recycling pool
                let _ = recycle_tx.send(buffer);
            }
        }
    }

    if let Ok(handle) = reader_thread {
        let _ = handle.join();
    }

    hits.sort_by_key(|h| (h.offset, h.sig_idx));
    hits.dedup_by(|a, b| a.offset == b.offset && a.sig_idx == b.sig_idx);
    Ok(hits)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Scan `path` for all known file signatures.
///
/// Automatically selects the fastest strategy:
/// - Regular files  →  `mmap` + `rayon` parallel scan
/// - Block devices  →  16 MB double-buffered async pipeline + rayon parallelism
pub fn scan_image(
    path:        &str,
    signatures:  &[FileSignature],
    cancel:      Arc<AtomicBool>,
    on_progress: ProgressFn,
) -> std::io::Result<Vec<HitEvent>> {
    scan_image_streaming(path, signatures, cancel, on_progress, None)
}

/// Scan `path` for all known file signatures with real-time progressive hit streaming.
/// As each signature match is detected in sector buffers, `on_hit` is invoked immediately
/// allowing concurrent extraction and live UI row updates.
pub fn scan_image_streaming(
    path:        &str,
    signatures:  &[FileSignature],
    cancel:      Arc<AtomicBool>,
    on_progress: ProgressFn,
    on_hit:      Option<HitFn>,
) -> std::io::Result<Vec<HitEvent>> {
    let norm  = normalise_path(path);
    let f     = open_source(&norm)?;
    let total = get_total_size(&f, &norm);

    if is_mappable(&f) {
        // Fast path: memory-mapped parallel scan
        scan_mmap(&f, total, signatures, cancel, on_progress, on_hit)
    } else {
        // Device path: buffered parallel scan
        scan_device(&norm, total, signatures, cancel, on_progress, on_hit)
    }
}
