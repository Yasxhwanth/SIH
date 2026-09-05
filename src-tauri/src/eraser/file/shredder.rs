// eraser/file/shredder.rs — File content overwrite + free-space wipe

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;
use crate::error::Result;

const BLOCK: usize = 64 * 1024; // 64 KB write blocks

/// Overwrite the content of a file with `passes` rounds:
///   Pass 1: zeros
///   Pass 2: 0xFF
///   Pass 3+: CSPRNG random
pub fn overwrite_file(path: &Path, passes: u8) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let size = f.seek(SeekFrom::End(0))?;
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; BLOCK];

    for pass in 0..passes {
        f.seek(SeekFrom::Start(0))?;
        let mut written: u64 = 0;
        while written < size {
            let chunk = ((size - written) as usize).min(BLOCK);
            match pass {
                0 => buf[..chunk].fill(0x00),
                1 => buf[..chunk].fill(0xFF),
                _ => rng.fill_bytes(&mut buf[..chunk]),
            }
            f.write_all(&buf[..chunk])?;
            written += chunk as u64;
        }
        f.flush()?;
        f.sync_all()?;
    }

    // Truncate to zero after passes — removes file content from filesystem
    f.set_len(0)?;
    Ok(())
}

/// Fill free space on a volume by creating a temp file and filling it
/// until the disk is full, then deleting it. This overwrites residual
/// unlinked file data in slack space.
pub fn wipe_slack_space(
    volume_path: &str,
    passes: u8,
    on_progress: impl Fn(u64, u64),
) -> Result<u64> {
    let temp_path = std::path::PathBuf::from(volume_path).join(".forensix_slack_wipe");
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; BLOCK];
    let mut total_written: u64 = 0;

    for pass in 0..passes {
        let mut f = File::create(&temp_path)?;
        let fill_byte: Option<u8> = match pass { 0 => Some(0x00), 1 => Some(0xFF), _ => None };

        loop {
            match fill_byte {
                Some(b) => buf.fill(b),
                None    => rng.fill_bytes(&mut buf),
            }
            match f.write_all(&buf) {
                Ok(_)  => { total_written += BLOCK as u64; on_progress(total_written, 0); }
                Err(_) => break, // disk full — expected
            }
        }
        f.flush().ok();
        std::fs::remove_file(&temp_path).ok();
    }

    Ok(total_written)
}
