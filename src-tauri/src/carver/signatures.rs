// carver/signatures.rs — File type signature database
//
// Each FileSignature describes how to detect a file type in a raw byte stream:
//   magic           : header bytes at `offset` that identify the type
//   footer          : optional end-of-file marker (None → use max_size cutoff)
//   max_size        : hard upper bound on extract size (bytes)
//   confidence_base : starting score before structural validation
//   extra_validation: name of per-type structural validator to run

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSignature {
    pub magic: Vec<u8>,
    pub offset: usize,
    pub extension: &'static str,
    pub description: &'static str,
    pub max_size: usize,
    pub confidence_base: f32,
    pub footer: Option<Vec<u8>>,
    /// How many bytes to scan ahead searching for the footer
    pub footer_window: usize,
    pub category: FileCategory,
    pub extra_validation: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileCategory {
    Image,
    Document,
    Archive,
    Audio,
    Video,
    Executable,
    Database,
    Certificate,
    Other,
}

impl FileCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image       => "Image",
            Self::Document    => "Document",
            Self::Archive     => "Archive",
            Self::Audio       => "Audio",
            Self::Video       => "Video",
            Self::Executable  => "Executable",
            Self::Database    => "Database",
            Self::Certificate => "Certificate",
            Self::Other       => "Other",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Self::Image       => "image",
            Self::Document    => "document",
            Self::Archive     => "archive",
            Self::Audio       => "audio",
            Self::Video       => "video",
            Self::Executable  => "executable",
            Self::Database    => "database",
            Self::Certificate => "certificate",
            Self::Other       => "other",
        }
    }
}

macro_rules! sig {
    (
        magic: $magic:expr,
        ext: $ext:expr,
        desc: $desc:expr,
        max_mb: $max_mb:expr,
        conf: $conf:expr,
        cat: $cat:expr
        $(, footer: $footer:expr)?
        $(, footer_window_mb: $fw:expr)?
        $(, validate: $val:expr)?
    ) => {
        FileSignature {
            magic:           $magic.to_vec(),
            offset:          0,
            extension:       $ext,
            description:     $desc,
            max_size:        $max_mb * 1024 * 1024,
            confidence_base: $conf,
            footer:          { let _f: Option<Vec<u8>> = None; $( let _f = Some($footer.to_vec()); )? _f },
            footer_window:   { let _fw: usize = 512 * 1024; $( let _fw: usize = $fw * 1024 * 1024; )? _fw },
            category:        $cat,
            extra_validation: { let _v: Option<&'static str> = None; $( let _v = Some($val); )? _v },
        }
    };
}

pub fn all_signatures() -> Vec<FileSignature> {
    use FileCategory::*;
    vec![
        // ── Images ────────────────────────────────────────────────────────
        sig!(magic: b"\xff\xd8\xff",   ext:"jpg",  desc:"JPEG Image",
             max_mb:30,  conf:0.90, cat:Image,
             footer: b"\xff\xd9", footer_window_mb:30, validate:"jpeg"),

        sig!(magic: b"\x89PNG\r\n\x1a\n", ext:"png", desc:"PNG Image",
             max_mb:50,  conf:0.95, cat:Image,
             footer: b"IEND\xaeB`\x82", footer_window_mb:50, validate:"png"),

        sig!(magic: b"GIF87a",  ext:"gif", desc:"GIF Image (87a)",
             max_mb:10,  conf:0.92, cat:Image,
             footer: b"\x00\x3b", footer_window_mb:10),

        sig!(magic: b"GIF89a",  ext:"gif", desc:"GIF Image (89a)",
             max_mb:10,  conf:0.92, cat:Image,
             footer: b"\x00\x3b", footer_window_mb:10),

        sig!(magic: b"BM",      ext:"bmp", desc:"BMP Image",
             max_mb:100, conf:0.80, cat:Image, validate:"bmp"),

        sig!(magic: b"\x49\x49\x2a\x00", ext:"tif", desc:"TIFF Image (LE)",
             max_mb:200, conf:0.88, cat:Image),

        sig!(magic: b"\x4d\x4d\x00\x2a", ext:"tif", desc:"TIFF Image (BE)",
             max_mb:200, conf:0.88, cat:Image),

        sig!(magic: b"8BPS",    ext:"psd", desc:"Adobe Photoshop Document",
             max_mb:500, conf:0.95, cat:Image),

        sig!(magic: b"\x00\x00\x01\x00", ext:"ico", desc:"Windows Icon",
             max_mb:10,  conf:0.80, cat:Image),

        sig!(magic: b"\x49\x49\x2a\x00\x10\x00\x00\x00CR", ext:"cr2", desc:"Canon RAW Image (CR2)",
             max_mb:200, conf:0.96, cat:Image),

        sig!(magic: b"<svg",    ext:"svg", desc:"Scalable Vector Graphics",
             max_mb:20,  conf:0.85, cat:Image, footer: b"</svg>", footer_window_mb:20),

        sig!(magic: b"RIFF",    ext:"webp", desc:"WebP Raster Image",
             max_mb:50,  conf:0.85, cat:Image),

        // ── Documents & Web ───────────────────────────────────────────────
        sig!(magic: b"%PDF-",   ext:"pdf", desc:"PDF Document",
             max_mb:500, conf:0.95, cat:Document,
             footer: b"%%EOF", footer_window_mb:1, validate:"pdf"),

        // ZIP also covers .docx/.xlsx/.pptx (OOXML container)
        sig!(magic: b"PK\x03\x04", ext:"zip", desc:"ZIP / Office Open XML (DOCX/XLSX/PPTX)",
             max_mb:4096, conf:0.90, cat:Archive,
             footer: b"PK\x05\x06", footer_window_mb:2, validate:"zip"),

        // Legacy Microsoft Office (OLE2 compound document)
        sig!(magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
             ext:"doc", desc:"MS Office OLE2 (DOC/XLS/PPT)",
             max_mb:100, conf:0.88, cat:Document),

        sig!(magic: b"{\\rtf1", ext:"rtf", desc:"Rich Text Format",
             max_mb:50,  conf:0.90, cat:Document, footer: b"}", footer_window_mb:50),

        sig!(magic: b"%!PS-Adobe-", ext:"ps", desc:"PostScript Document",
             max_mb:100, conf:0.90, cat:Document),

        sig!(magic: b"<?xml ",  ext:"xml", desc:"XML Data Document",
             max_mb:50,  conf:0.85, cat:Document),

        sig!(magic: b"<!DOCTYPE html", ext:"html", desc:"HTML Web Document",
             max_mb:30,  conf:0.85, cat:Document),

        sig!(magic: b"<html",   ext:"html", desc:"HTML Document (alt)",
             max_mb:30,  conf:0.80, cat:Document),

        sig!(magic: b"{\"",     ext:"json", desc:"JSON Data Object",
             max_mb:50,  conf:0.75, cat:Document, validate:"json"),

        // ── Archives & Containers ─────────────────────────────────────────
        sig!(magic: b"Rar!\x1a\x07\x00",     ext:"rar", desc:"RAR Archive v4",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"Rar!\x1a\x07\x01\x00", ext:"rar", desc:"RAR Archive v5",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"7z\xbc\xaf\x27\x1c",   ext:"7z",  desc:"7-Zip Archive",
             max_mb:4096, conf:0.97, cat:Archive),
        sig!(magic: b"\x1f\x8b\x08",          ext:"gz",  desc:"Gzip Compressed",
             max_mb:4096, conf:0.92, cat:Archive),
        sig!(magic: b"BZh",                   ext:"bz2", desc:"Bzip2 Compressed",
             max_mb:4096, conf:0.90, cat:Archive),
        sig!(magic: b"\xfd7zXZ\x00",          ext:"xz",  desc:"XZ Compressed Archive",
             max_mb:4096, conf:0.96, cat:Archive),
        sig!(magic: b"MSCF",                  ext:"cab", desc:"Microsoft Cabinet Archive",
             max_mb:500, conf:0.92, cat:Archive),
        sig!(magic: b"conectix",              ext:"vhd", desc:"Virtual Hard Disk (VHD)",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"KDMV",                  ext:"vmdk", desc:"VMware Virtual Disk (VMDK)",
             max_mb:4096, conf:0.95, cat:Archive),

        // ── Audio ─────────────────────────────────────────────────────────
        sig!(magic: b"ID3",     ext:"mp3", desc:"MP3 Audio (ID3 tag)",
             max_mb:200, conf:0.85, cat:Audio),
        sig!(magic: b"\xff\xfb",ext:"mp3", desc:"MP3 Audio (frame sync)",
             max_mb:200, conf:0.70, cat:Audio, validate:"mp3"),
        sig!(magic: b"RIFF",    ext:"wav", desc:"WAV Audio / Resource Container",
             max_mb:500, conf:0.75, cat:Audio, validate:"wav"),
        sig!(magic: b"OggS",    ext:"ogg", desc:"Ogg Container (Vorbis/Opus)",
             max_mb:500, conf:0.95, cat:Audio),
        sig!(magic: b"fLaC",    ext:"flac",desc:"FLAC Lossless Audio",
             max_mb:500, conf:0.97, cat:Audio),
        sig!(magic: b"MThd",    ext:"mid", desc:"Standard MIDI Sequence",
             max_mb:20,  conf:0.95, cat:Audio),
        sig!(magic: b"\xff\xf1",ext:"aac", desc:"MPEG-4 AAC Audio (ADTS)",
             max_mb:200, conf:0.80, cat:Audio, validate:"aac"),
        sig!(magic: b"\xff\xf9",ext:"aac", desc:"MPEG-2 AAC Audio (ADTS)",
             max_mb:200, conf:0.80, cat:Audio, validate:"aac"),
        sig!(magic: b"\x30\x26\xb2\x75\x8e\x66\xcf\x11", ext:"wma", desc:"Windows Media Audio/Video (ASF)",
             max_mb:2000, conf:0.95, cat:Audio),

        // ── Video ─────────────────────────────────────────────────────────
        sig!(magic: b"\x00\x00\x00\x18ftypmp4", ext:"mp4", desc:"MP4 Video (ISO Base)",
             max_mb:4096, conf:0.90, cat:Video, validate:"mp4"),
        sig!(magic: b"\x00\x00\x00\x20ftyp",    ext:"mp4", desc:"MP4 Video (Generic)",
             max_mb:4096, conf:0.85, cat:Video, validate:"mp4"),
        sig!(magic: b"\x00\x00\x00\x14ftypqt  ", ext:"mov", desc:"Apple QuickTime Video",
             max_mb:4096, conf:0.92, cat:Video),
        sig!(magic: b"\x00\x00\x00\x20ftypqt  ", ext:"mov", desc:"Apple QuickTime Video (alt)",
             max_mb:4096, conf:0.90, cat:Video),
        sig!(magic: b"\x00\x00\x00\x18ftyp3gp", ext:"3gp", desc:"3GPP Multimedia Video",
             max_mb:500, conf:0.90, cat:Video),
        sig!(magic: b"\x1aE\xdf\xa3", ext:"mkv", desc:"Matroska / WebM Video",
             max_mb:4096, conf:0.90, cat:Video),
        sig!(magic: b"FLV\x01", ext:"flv", desc:"Flash Video",
             max_mb:2000, conf:0.92, cat:Video),

        // ── Executables & Bytecode ─────────────────────────────────────────
        sig!(magic: b"\x7fELF", ext:"elf",   desc:"ELF Executable (Linux)",
             max_mb:500, conf:0.97, cat:Executable, validate:"elf"),
        sig!(magic: b"MZ",      ext:"exe",   desc:"PE Executable / DLL (Windows)",
             max_mb:500, conf:0.80, cat:Executable, validate:"pe"),
        sig!(magic: b"\xca\xfe\xba\xbe", ext:"macho", desc:"Mach-O Fat Binary / Java Class",
             max_mb:500, conf:0.95, cat:Executable),
        sig!(magic: b"\xcf\xfa\xed\xfe", ext:"macho", desc:"Mach-O 64-bit Binary",
             max_mb:500, conf:0.95, cat:Executable),
        sig!(magic: b"\x00asm", ext:"wasm",  desc:"WebAssembly Binary",
             max_mb:100, conf:0.95, cat:Executable),
        sig!(magic: b"dex\n035\x00", ext:"dex", desc:"Android Dalvik Executable",
             max_mb:100, conf:0.98, cat:Executable),

        // ── Databases, Forensics & System Artifacts ────────────────────────
        sig!(magic: b"SQLite format 3\x00", ext:"sqlite", desc:"SQLite Database",
             max_mb:4096, conf:0.99, cat:Database),
        sig!(magic: b"regf",    ext:"dat",   desc:"Windows Registry Hive",
             max_mb:500, conf:0.95, cat:Database),
        sig!(magic: b"ElfFile\x00", ext:"evtx", desc:"Windows Event Log (EVTX)",
             max_mb:500, conf:0.98, cat:Database),
        sig!(magic: b"\xd4\xc3\xb2\xa1", ext:"pcap", desc:"Wireshark/tcpdump PCAP (LE)",
             max_mb:2000, conf:0.95, cat:Database),
        sig!(magic: b"\xa1\xb2\xc3\xd4", ext:"pcap", desc:"Wireshark/tcpdump PCAP (BE)",
             max_mb:2000, conf:0.95, cat:Database),
        sig!(magic: b"\x0a\x0d\x0d\x0a", ext:"pcapng", desc:"PCAP Next Generation Capture",
             max_mb:2000, conf:0.95, cat:Database),

        // ── Security, Keys & Wallets ──────────────────────────────────────
        sig!(magic: b"-----BEGIN ", ext:"pem", desc:"PEM Certificate / Private Key",
             max_mb:1, conf:0.85, cat:Certificate,
             footer: b"-----END ", footer_window_mb:1, validate:"pem"),
        sig!(magic: b"AKIA", ext:"key", desc:"AWS Access Key ID",
             max_mb:1, conf:0.92, cat:Certificate, validate:"aws_key"),
        sig!(magic: b"ghp_", ext:"token", desc:"GitHub Personal Access Token",
             max_mb:1, conf:0.95, cat:Certificate, validate:"github_pat"),
        sig!(magic: b"eyJ", ext:"jwt", desc:"JSON Web Token (JWT Bearer)",
             max_mb:1, conf:0.90, cat:Certificate, validate:"jwt"),
        sig!(magic: b"{\"crypto\":{\"", ext:"json", desc:"Ethereum Web3 Keystore",
             max_mb:1, conf:0.95, cat:Certificate, validate:"eth_keystore"),
        sig!(magic: b"-----BEGIN PGP ", ext:"asc", desc:"PGP Armored Security Key",
             max_mb:2, conf:0.90, cat:Certificate),
        sig!(magic: b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", ext:"kdbx", desc:"KeePass 2.x Password Database",
             max_mb:100, conf:0.99, cat:Certificate),
        sig!(magic: b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5", ext:"kdb", desc:"KeePass 1.x Password Database",
             max_mb:100, conf:0.99, cat:Certificate),
        sig!(magic: b"\x00\x05\x31\x62", ext:"wallet", desc:"Bitcoin Core Berkeley DB Wallet",
             max_mb:100, conf:0.95, cat:Certificate),

        // ── Camera RAW & Digital Photography (Professional DSLR/Mirrorless) ──
        sig!(magic: b"\x00\x00\x00\x18ftypcrx ", ext:"cr3", desc:"Canon RAW v3 (CR3)",
             max_mb:250, conf:0.96, cat:Image),
        sig!(magic: b"FUJIFILMCCD-RAW ", ext:"raf", desc:"Fujifilm RAW Image (RAF)",
             max_mb:200, conf:0.97, cat:Image),
        sig!(magic: b"IIRO\x08\x00\x00\x00", ext:"orf", desc:"Olympus RAW Image (ORF)",
             max_mb:200, conf:0.96, cat:Image),
        sig!(magic: b"IIU\x00\x08\x00\x00\x00", ext:"rw2", desc:"Panasonic Lumix RAW (RW2)",
             max_mb:200, conf:0.96, cat:Image),
        sig!(magic: b"\x49\x49\x2a\x00\x08\x00\x00\x00", ext:"arw", desc:"Sony Alpha RAW (ARW)",
             max_mb:250, conf:0.95, cat:Image),
        sig!(magic: b"DDS ", ext:"dds", desc:"DirectDraw Surface Texture",
             max_mb:100, conf:0.90, cat:Image),
        sig!(magic: b"\x76\x2f\x31\x01", ext:"exr", desc:"OpenEXR HDR Image",
             max_mb:500, conf:0.95, cat:Image),
        sig!(magic: b"8BPS\x00\x02", ext:"psb", desc:"Adobe Photoshop Big (PSB)",
             max_mb:2048, conf:0.95, cat:Image),
        sig!(magic: b"\xc5\xd0\xd3\xc6", ext:"eps", desc:"Encapsulated PostScript (EPS)",
             max_mb:100, conf:0.92, cat:Image),
        sig!(magic: b"\x00\x00\x00\x18ftypheic", ext:"heic", desc:"High Efficiency Image (HEIC)",
             max_mb:100, conf:0.95, cat:Image),
        sig!(magic: b"\x00\x00\x00\x18ftypmif1", ext:"heif", desc:"High Efficiency Image Sequence (HEIF)",
             max_mb:100, conf:0.95, cat:Image),
        sig!(magic: b"\x00\x00\x00\x1cftypavif", ext:"avif", desc:"AV1 Still Image (AVIF)",
             max_mb:100, conf:0.95, cat:Image),
        sig!(magic: b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a", ext:"jxl", desc:"JPEG XL Image (JXL)",
             max_mb:100, conf:0.97, cat:Image),

        // ── Engineering, CAD & 3D Formats ─────────────────────────────────
        sig!(magic: b"AC1015", ext:"dwg", desc:"AutoCAD 2000 Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"AC1018", ext:"dwg", desc:"AutoCAD 2004 Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"AC1021", ext:"dwg", desc:"AutoCAD 2007 Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"AC1024", ext:"dwg", desc:"AutoCAD 2010 Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"AC1027", ext:"dwg", desc:"AutoCAD 2013 Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"AC1032", ext:"dwg", desc:"AutoCAD 2018+ Drawing (DWG)",
             max_mb:500, conf:0.96, cat:Document),
        sig!(magic: b"BLENDER", ext:"blend", desc:"Blender 3D Project File",
             max_mb:2000, conf:0.98, cat:Document),
        sig!(magic: b"glTF", ext:"glb", desc:"glTF 2.0 Binary 3D Asset",
             max_mb:1000, conf:0.95, cat:Document),
        sig!(magic: b"Kaydara FBX Binary\x20\x20\x00\x1a\x00", ext:"fbx", desc:"Autodesk FBX 3D Model",
             max_mb:1000, conf:0.99, cat:Document),

        // ── Advanced Publishing, E-Books & Specialized Documents ──────────
        sig!(magic: b"ITSF\x03\x00\x00\x00", ext:"chm", desc:"Microsoft Compiled HTML Help",
             max_mb:200, conf:0.95, cat:Document),
        sig!(magic: b"\xffWPC", ext:"wpd", desc:"Corel WordPerfect Document",
             max_mb:100, conf:0.90, cat:Document),
        sig!(magic: b"\x06\x06\xed\xf5\xd8\x1d\x46\xe5\xbd\x31\xef\xe7\xfe\x74\xb7\x1d", ext:"indd", desc:"Adobe InDesign Document",
             max_mb:1000, conf:0.99, cat:Document),

        // ── Advanced Audio & Musical Codecs ───────────────────────────────
        sig!(magic: b"\x00\x00\x00\x20ftypM4A ", ext:"m4a", desc:"Apple MPEG-4 Audio (ALAC/AAC)",
             max_mb:500, conf:0.92, cat:Audio),
        sig!(magic: b"MAC ", ext:"ape", desc:"Monkey's Audio Lossless",
             max_mb:500, conf:0.95, cat:Audio),
        sig!(magic: b"MPCK", ext:"mpc", desc:"Musepack Audio Stream",
             max_mb:200, conf:0.95, cat:Audio),
        sig!(magic: b"\x0b\x77", ext:"ac3", desc:"Dolby Digital AC-3 Audio",
             max_mb:500, conf:0.75, cat:Audio),
        sig!(magic: b"Creative Voice File", ext:"voc", desc:"Creative Labs Sound Blaster VOC",
             max_mb:100, conf:0.98, cat:Audio),
        sig!(magic: b"Extended Module: ", ext:"xm", desc:"FastTracker II Extended Module",
             max_mb:30, conf:0.98, cat:Audio),

        // ── Broadcast & High-End Video Formats ────────────────────────────
        sig!(magic: b"\x00\x00\x01\xba", ext:"mpg", desc:"MPEG-1/2 Program Stream / DVD VOB",
             max_mb:4096, conf:0.85, cat:Video),
        sig!(magic: b"\x47\x40\x00\x10", ext:"ts", desc:"MPEG-2 Transport Stream (BDAV/M2TS)",
             max_mb:4096, conf:0.85, cat:Video),
        sig!(magic: b"\x06\x0e\x2b\x34\x02\x05\x01\x01", ext:"mxf", desc:"SMPTE Material Exchange Format",
             max_mb:4096, conf:0.95, cat:Video),
        sig!(magic: b".RMF\x00\x00\x00", ext:"rm", desc:"RealMedia Streaming Container",
             max_mb:2000, conf:0.95, cat:Video),
        sig!(magic: b"BIKi", ext:"bik", desc:"RAD Game Tools Bink Video",
             max_mb:2000, conf:0.96, cat:Video),

        // ── Modern Archives, Virtualization & Hypervisors ─────────────────
        sig!(magic: b"\x28\xb5\x2f\xfd", ext:"zst", desc:"Zstandard Compressed Archive",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"\x04\x22\x4d\x18", ext:"lz4", desc:"LZ4 Frame Compressed Archive",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"-lh5-", ext:"lzh", desc:"LHA Compressed Archive",
             max_mb:500, conf:0.92, cat:Archive),
        sig!(magic: b"\x60\xea", ext:"arj", desc:"ARJ Compressed Archive",
             max_mb:500, conf:0.90, cat:Archive),
        sig!(magic: b"<<< Oracle VM VirtualBox Disk Image >>>", ext:"vdi", desc:"VirtualBox Disk Image (VDI)",
             max_mb:4096, conf:0.99, cat:Archive),
        sig!(magic: b"vhdxfile", ext:"vhdx", desc:"Microsoft Hyper-V Virtual Disk v2",
             max_mb:4096, conf:0.99, cat:Archive),
        sig!(magic: b"QFI\xfb", ext:"qcow2", desc:"QEMU Copy-On-Write Disk Image v2/v3",
             max_mb:4096, conf:0.98, cat:Archive),
        sig!(magic: b"hsqs", ext:"squashfs", desc:"Squashfs Compressed Filesystem (LE)",
             max_mb:4096, conf:0.95, cat:Archive),
        sig!(magic: b"\x53\xef", ext:"ext4", desc:"Linux Ext2/Ext3/Ext4 Superblock",
             max_mb:4096, conf:0.85, cat:Archive),
        sig!(magic: b"MSWIM\x00\x00\x00", ext:"wim", desc:"Windows Imaging Format Archive",
             max_mb:4096, conf:0.98, cat:Archive),

        // ── Bytecode, Mobile & Packages ───────────────────────────────────
        sig!(magic: b"\x55\x0d\x0d\x0a", ext:"pyc", desc:"Python 3.8 Bytecode",
             max_mb:50, conf:0.95, cat:Executable),
        sig!(magic: b"\x61\x0d\x0d\x0a", ext:"pyc", desc:"Python 3.9 Bytecode",
             max_mb:50, conf:0.95, cat:Executable),
        sig!(magic: b"\x6f\x0d\x0d\x0a", ext:"pyc", desc:"Python 3.10 Bytecode",
             max_mb:50, conf:0.95, cat:Executable),
        sig!(magic: b"\xa7\x0d\x0d\x0a", ext:"pyc", desc:"Python 3.11 Bytecode",
             max_mb:50, conf:0.95, cat:Executable),
        sig!(magic: b"\xcb\x0d\x0d\x0a", ext:"pyc", desc:"Python 3.12 Bytecode",
             max_mb:50, conf:0.95, cat:Executable),
        sig!(magic: b"\x1bLua", ext:"luac", desc:"Lua Compiled Bytecode",
             max_mb:50, conf:0.96, cat:Executable),
        sig!(magic: b"\x02\x00\x0c\x00", ext:"arsc", desc:"Android Compiled Resource Table",
             max_mb:100, conf:0.95, cat:Executable),
        sig!(magic: b"\xed\xab\xee\xdb", ext:"rpm", desc:"Red Hat Package Manager (RPM)",
             max_mb:2000, conf:0.98, cat:Executable),

        // ── Digital Forensics, OS Artifacts & Memory (NTRO Advantage) ─────
        sig!(magic: b"MAM\x04", ext:"pf", desc:"Windows 8.1/10/11 Prefetch Artifact",
             max_mb:20, conf:0.98, cat:Database),
        sig!(magic: b"SCCA", ext:"pf", desc:"Windows 7/XP Prefetch Execution Artifact",
             max_mb:20, conf:0.98, cat:Database),
        sig!(magic: b"MDMP\x93\xa7", ext:"dmp", desc:"Windows User/Kernel Minidump",
             max_mb:500, conf:0.99, cat:Database),
        sig!(magic: b"EMiL", ext:"lime", desc:"LiME Linux Memory Acquisition Header",
             max_mb:4096, conf:0.98, cat:Database),
        sig!(magic: b"-FVE-FS-", ext:"fve", desc:"Microsoft BitLocker Volume Encryption Header",
             max_mb:10, conf:0.99, cat:Certificate),
        sig!(magic: b"\xef\xcd\xab\x89", ext:"edb", desc:"Windows Search / Active Directory ESE DB",
             max_mb:4096, conf:0.95, cat:Database),
        sig!(magic: b"\x4c\x00\x00\x00\x01\x14\x02\x00", ext:"lnk", desc:"Windows Shell Shortcut Link",
             max_mb:10, conf:0.98, cat:Database),

        // ── VPN, Cloud Secrets, Crypto & Defense Tokens ───────────────────
        sig!(magic: b"[Interface]", ext:"conf", desc:"WireGuard VPN Private Configuration",
             max_mb:1, conf:0.90, cat:Certificate),
        sig!(magic: b"-----BEGIN OPENSSH PRIVATE KEY-----", ext:"key", desc:"OpenSSH Private Key (RSA/Ed25519)",
             max_mb:1, conf:0.99, cat:Certificate),
        sig!(magic: b"\x01\x11\x01\x01", ext:"keys", desc:"Monero Crypto Private Key Container",
             max_mb:10, conf:0.95, cat:Certificate),
        sig!(magic: b"{\n  \"type\": \"service_account\"", ext:"json", desc:"Google Cloud Service Account JSON Key",
             max_mb:1, conf:0.98, cat:Certificate),
        sig!(magic: b"sk_live_", ext:"key", desc:"Stripe Live Secret Key",
             max_mb:1, conf:0.95, cat:Certificate),
        sig!(magic: b"xoxb-", ext:"token", desc:"Slack Bot OAuth Secret Token",
             max_mb:1, conf:0.95, cat:Certificate),
    ]
}

/// Build a first-byte index: byte_value → [signature indices]
pub fn build_index(sigs: &[FileSignature]) -> [Vec<usize>; 256] {
    let mut idx: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, sig) in sigs.iter().enumerate() {
        if !sig.magic.is_empty() {
            idx[sig.magic[0] as usize].push(i);
        }
    }
    idx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCatalogStats {
    pub total_signatures: usize,
    pub total_extensions: usize,
    pub category_counts: std::collections::HashMap<String, usize>,
}

pub fn get_catalog_stats() -> SignatureCatalogStats {
    let sigs = all_signatures();
    let mut category_counts = std::collections::HashMap::new();
    for s in &sigs {
        *category_counts.entry(s.category.as_str().to_string()).or_insert(0) += 1;
    }
    SignatureCatalogStats {
        total_signatures: sigs.len(),
        total_extensions: SUPPORTED_EXTENSIONS.len(),
        category_counts,
    }
}

/// Comprehensive catalog of 420+ recognized file extensions across all supported formats and container variations.
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    // Raw Photography & Camera RAW (42)
    "cr2", "cr3", "crw", "nef", "nrw", "arw", "srf", "sr2", "raf", "orf", "rw2", "raw", "pef", "ptx", "dng",
    "3fr", "erf", "kdc", "dcr", "mos", "mrw", "x3f", "mef", "rwl", "iiq", "srw", "ari", "bay", "cap", "fff",
    "dcs", "drf", "k25", "mdc", "obm", "qtk", "rdc", "rwz", "cine", "eip", "ia", "pxn",
    // Raster, Vector & 2D Graphics (46)
    "jpg", "jpeg", "jpe", "jif", "jfif", "jfi", "png", "gif", "bmp", "dib", "tif", "tiff", "webp", "heic", "heif",
    "avif", "jxl", "svg", "svgz", "ico", "cur", "psd", "psb", "xcf", "ai", "eps", "cdr", "cgm", "wmf", "emf",
    "art", "xpm", "xbm", "pcx", "tga", "exr", "hdr", "dds", "pbm", "pgm", "ppm", "pnm", "wbmp", "bpg", "iff", "lbm",
    // Office, Documents & E-Books (54)
    "pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "xltm",
    "ppt", "pptx", "pptm", "pot", "potx", "potm", "pps", "ppsx", "ppsm", "odt", "ods", "odp", "odg", "odf",
    "rtf", "txt", "csv", "tsv", "xml", "json", "html", "htm", "xhtml", "chm", "hlp", "epub", "mobi", "azw",
    "azw3", "fb2", "lit", "prc", "pages", "numbers", "key", "vsd", "vsdx", "mpp", "pub", "wpd",
    // Engineering, CAD, GIS & 3D (36)
    "dwg", "dxf", "dgn", "blend", "glb", "gltf", "fbx", "obj", "stl", "3ds", "max", "c4d", "ma", "mb", "skp",
    "dae", "ply", "step", "stp", "iges", "igs", "sldprt", "sldasm", "dwf", "kml", "kmz", "gpx", "shp", "shx",
    "dbf", "osm", "geojson", "dem", "las", "laz", "ifc",
    // Archives, Virtual Disks & Filesystems (58)
    "zip", "zipx", "rar", "7z", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "lz4", "lzma", "lzh",
    "lha", "arj", "cab", "iso", "img", "bin", "cue", "nrg", "mdf", "vhd", "vhdx", "vmdk", "vdi", "qcow", "qcow2",
    "dmg", "pkg", "wim", "swm", "esd", "squashfs", "ext4", "ext3", "ext2", "btrfs", "xfs", "zfs", "fat", "ntfs",
    "hfs", "apfs", "cpio", "shar", "z", "lz", "uue", "ace", "arc", "pak", "chm", "msi", "msp", "deb",
    // Audio & Musical Formats (44)
    "mp3", "wav", "flac", "ogg", "oga", "opus", "aac", "m4a", "m4b", "wma", "aif", "aiff", "aifc", "ape", "mpc",
    "ac3", "dts", "mid", "midi", "kar", "mod", "xm", "it", "s3m", "voc", "au", "snd", "ra", "ram", "amr",
    "awb", "gsm", "qcp", "alac", "dsd", "dsf", "dff", "cda", "mka", "shn", "tta", "wv", "act", "m4p",
    // Video & Streaming Media (44)
    "mp4", "m4v", "mkv", "mov", "qt", "avi", "wmv", "asf", "flv", "f4v", "webm", "3gp", "3g2", "mpg", "mpeg",
    "mpe", "mpv", "m2v", "vob", "evo", "ts", "m2ts", "mts", "mxf", "rm", "rmvb", "ogv", "bik", "smk", "roq",
    "divx", "xvid", "y4m", "ivf", "h264", "h265", "hevc", "avc", "m4s", "dv", "flic", "fli", "flc", "swf",
    // Executables, Bytecode, Scripts & Mobile (44)
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "efi", "elf", "so", "o", "a", "dylib", "macho", "class",
    "jar", "war", "ear", "dex", "apk", "aab", "arsc", "wasm", "wat", "pyc", "pyo", "pyd", "luac", "rpm",
    "crx", "xpi", "bundle", "app", "ipa", "ko", "prg", "vbs", "bat", "ps1", "sh", "pl", "py", "rb", "js",
    // Forensics, Incident Response, Cryptography & Databases (60)
    "sqlite", "sqlite3", "db", "db3", "s3db", "wal", "shm", "dat", "reg", "hive", "evtx", "evt", "pcap",
    "pcapng", "cap", "dmp", "mdmp", "lime", "mem", "raw", "vmem", "fve", "edb", "dit", "ntds", "lnk", "pf",
    "automaticDestinations-ms", "customDestinations-ms", "kdbx", "kdb", "wallet", "key", "pem", "crt", "cer",
    "pfx", "p12", "der", "csr", "asc", "gpg", "pgp", "token", "jwt", "conf", "ovpn", "rdp", "vnc", "tc",
    "vc", "hc", "accdb", "mdb", "mdf", "ldf", "frm", "ibd", "myd", "frm"
];
