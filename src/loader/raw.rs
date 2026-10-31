//! Raw blobs (shellcode, firmware, unknown data): one RWX region at `--base`.

use std::path::PathBuf;

use super::LoadOptions;
use crate::model::*;

pub fn load(path: PathBuf, data: Data, opts: &LoadOptions) -> Binary {
    let len = data.slice().len() as u64;
    let base = opts.base.unwrap_or(0);
    let (arch, bits, endian, thumb) = match &opts.arch {
        Some(s) => (s.arch.clone(), s.bits, s.endian, s.thumb),
        None => (Arch::Unknown("unknown".into()), 0, Endian::Little, false),
    };
    let rwx = Perms::new(true, true, true);
    let info = RawInfo {
        magic: describe_magic(data.slice()).map(str::to_string),
        arch_specified: opts.arch.is_some(),
    };
    Binary {
        path,
        format: Format::Raw,
        kind: FileKind::Other,
        arch,
        bits,
        endian,
        thumb,
        os: "-".into(),
        abi: None,
        entry: opts.arch.is_some().then_some(base),
        image_base: base,
        file_size: data.file().len() as u64,
        sections: vec![Section {
            index: 0,
            name: "raw".into(),
            segment: None,
            addr: base,
            size: len,
            offset: 0,
            file_size: len,
            perms: rwx,
            kind: "blob".into(),
            flags: 0,
            alloc: true,
            tls: false,
        }],
        segments: Vec::new(),
        regions: vec![Region {
            name: "raw".into(),
            va: base,
            vsize: len,
            offset: 0,
            file_size: len,
            perms: rwx,
        }],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        relocations: Vec::new(),
        libraries: Vec::new(),
        interpreter: None,
        details: Details::Raw(info),
        warnings: Vec::new(),
        data,
    }
}

/// Recognise common non-executable containers so raw blobs get a useful label.
pub fn describe_magic(b: &[u8]) -> Option<&'static str> {
    const TABLE: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "ZIP archive (JAR/APK/Office)"),
        (b"\x1f\x8b", "gzip compressed data"),
        (b"%PDF", "PDF document"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"!<arch>\n", "ar archive (static library)"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"\xfd7zXZ\x00", "xz compressed data"),
        (b"BZh", "bzip2 compressed data"),
        (b"\x28\xb5\x2f\xfd", "Zstandard compressed data"),
        (b"\x04\x22\x4d\x18", "LZ4 compressed data"),
        (b"\0asm", "WebAssembly module"),
        (b"dex\n", "Android DEX bytecode"),
        (b"\xca\xfe\xba\xbe", "Java class file"),
        (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "OLE2 compound document (Office/MSI)",
        ),
        (b"{\\rtf", "RTF document"),
        (b"SQLite format 3\0", "SQLite database"),
        (b"hsqs", "SquashFS filesystem"),
        (b"\x27\x05\x19\x56", "U-Boot legacy image"),
        (b"\xd0\x0d\xfe\xed", "device tree blob"),
        (b"MZ", "MS-DOS executable (no PE header)"),
        (b"#!", "script (shebang)"),
    ];
    TABLE
        .iter()
        .find(|(magic, _)| b.starts_with(magic))
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_blob_with_arch_and_base() {
        let opts = LoadOptions {
            arch: ArchSpec::parse("x86-64"),
            base: Some(0x1000),
            slice: None,
        };
        let b = load("sc.bin".into(), Data::from_vec(vec![0x90; 32]), &opts);
        assert_eq!(b.arch, Arch::X86_64);
        assert_eq!(b.entry, Some(0x1000));
        assert_eq!(b.va_to_offset(0x1010), Ok(0x10));
        assert!(b.va_to_offset(0x1020).is_err());
    }

    #[test]
    fn magic_table() {
        assert_eq!(
            describe_magic(b"PK\x03\x04rest"),
            Some("ZIP archive (JAR/APK/Office)")
        );
        assert_eq!(describe_magic(b"\x00\x01"), None);
    }
}
