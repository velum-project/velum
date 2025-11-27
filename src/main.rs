//! src/main.rs
//!
//! Command-line interface for VELUM v1 — a post-quantum, recipient-anonymous,
//! hybrid end-to-end encryption tool with zero-seek streaming and hybrid signatures.
//!
//! This binary provides a secure, user-friendly, Unix-philosophy-compliant CLI that
//! supports:
//! - Key generation with encrypted secret keystores (Argon2id + AES-GCM-SIV)
//! - In-RAM and zero-seek streaming encryption/decryption
//! - Hybrid post-quantum signatures (ML-DSA-65 + Ed25519)
//! - Full armor (ASCII) and binary formats
//! - Automatic input format detection
//! - Secure TTY handling (no raw binary to terminal)
//! - Progress reporting with speed statistics
//! - Password change (rewrap) with adjustable KDF parameters

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use is_terminal::IsTerminal;

use velum_core::{
    core::SigStatus,
    decrypt,
    decrypt_file_stream,
    encrypt,
    encrypt_binary,
    encrypt_file_stream,
    generate_keypair,
    rewrap_secret_with_params,
};

/// Default chunk size for streaming mode (4 MiB) — optimal balance of memory and performance.
const DEFAULT_CHUNK_SIZE: usize = 4 << 20; // 4 MiB

/// Maximum safe chunk size in streaming mode.
///
/// This is the largest chunk size that won't produce a frame length that collides
/// with the trailer sentinel (`0xFFFFFFFF`).
///
/// Frame length = chunk_size + TAG_LEN (16) + nonce overhead
/// Must ensure: chunk_size + TAG_LEN < 0xFFFFFFFF
const MAX_SAFE_CHUNK_SIZE: usize = 0xFFFF_FFFE - 16; // ~4.29 GB

/// Minimum recommended chunk size (64 KiB).
///
/// Smaller chunks increase overhead and reduce throughput.
const MIN_RECOMMENDED_CHUNK_SIZE: usize = 64 * 1024;

/// Armored message header — used for auto-detection.
const BEGIN_MSG: &str = "-----BEGIN VELUM MESSAGE-----";

/// Hard limit on number of recipients (prevents accidental DoS via huge recipient lists).
const RECIP_HARD_LIMIT: usize = 512;

/// Main CLI parser powered by `clap`.
#[derive(Parser, Debug)]
#[command(name = "velum", version, about = "VELUM v1 — post-quantum hybrid encryption CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new keypair (PUBLIC + encrypted SECRET keystore).
    Keygen {
        #[arg(long)]
        /// Output path for the public key (defaults to stdout)
        out_pub: Option<PathBuf>,

        #[arg(long)]
        /// Output path for the encrypted secret key (defaults to stdout)
        out_sec: Option<PathBuf>,

        #[arg(long, env = "VELUM_PASS")]
        /// Passphrase for the secret key (prompted securely if omitted)
        pass: Option<String>,
    },

    /// Encrypt a message or file.
    Encrypt {
        #[arg(short = 'i', long, default_value = "-")]
        /// Input file or stdin ("-" for stdin)
        input: String,

        #[arg(short = 'o', long, default_value = "-")]
        /// Output file or stdout ("-" for stdout)
        output: String,

        #[arg(short = 'r', long, required = true)]
        /// One or more recipient PUBLIC key files (can be repeated)
        recipient: Vec<PathBuf>,

        #[arg(long)]
        /// Sign the ciphertext using this SECRET key file
        signer_secret: Option<PathBuf>,

        #[arg(long, env = "VELUM_SIGN_PASS")]
        /// Passphrase for the signing key (prompted if omitted)
        signer_pass: Option<String>,

        #[arg(long)]
        /// Enable zero-seek streaming mode (required for large files and pipes)
        stream: bool,

        #[arg(long)]
        /// Chunk size in streaming mode (default: 4 MiB)
        chunk_size: Option<usize>,

        #[arg(long)]
        /// Output ASCII-armored text (only valid in non-streaming mode)
        armor: bool,

        /// Allow more than 512 recipients (not recommended — potential DoS vector)
        #[arg(long)]
        allow_many_recipients: bool,
    },

    /// Decrypt a message or file.
    Decrypt {
        #[arg(short = 'i', long, default_value = "-")]
        input: String,

        #[arg(short = 'o', long, default_value = "-")]
        output: String,

        #[arg(long, required = true)]
        /// Your encrypted SECRET key file
        secret: PathBuf,

        #[arg(long, env = "VELUM_PASS")]
        /// Your passphrase (prompted securely if omitted)
        pass: Option<String>,

        #[arg(long)]
        /// Expect and verify a hybrid signature from this PUBLIC key
        expect_public: Option<PathBuf>,

        #[arg(long)]
        /// Force interpretation as armored input (skip auto-detection)
        armor_input: bool,

        #[arg(long)]
        /// Force interpretation as binary VLM1 input (skip auto-detection)
        binary_input: bool,
    },

    /// Change passphrase or KDF parameters of an existing SECRET key.
    Rewrap {
        #[arg(long, required = true)]
        /// Input SECRET key file to rewrap
        input_secret: PathBuf,

        #[arg(long, default_value = "-")]
        /// Output file ("-" for stdout)
        output: String,

        #[arg(long, env = "VELUM_OLD_PASS")]
        old_pass: Option<String>,

        #[arg(long, env = "VELUM_NEW_PASS")]
        new_pass: Option<String>,

        #[arg(long)]
        /// Memory cost in MiB (default: 96)
        m_mib: Option<u32>,

        #[arg(long)]
        /// Iteration count (default: 4)
        t_cost: Option<u32>,

        #[arg(long)]
        /// Parallelism factor (default: 4)
        parallelism: Option<u32>,
    },
}

/// Securely prompt for a hidden passphrase using `rpassword`.
fn prompt_hidden(label: &str) -> Result<String> {
    let s = rpassword::prompt_password(format!("{label}: ")).map_err(|e| anyhow!(e))?;
    if s.trim().is_empty() {
        bail!("Passphrase cannot be empty");
    }
    Ok(s)
}

/// Read entire input from file or stdin into memory.
fn read_all(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().lock().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("Cannot read: {path}"))
    }
}

/// Write data to file or stdout.
fn write_all(path: &str, data: &[u8]) -> std::io::Result<()> {
    if path == "-" {
        io::stdout().lock().write_all(data)
    } else {
        fs::write(path, data)
    }
}

/// Detect if data appears to be an armored VELUM message.
fn is_armored(buf: &[u8]) -> bool {
    buf.starts_with(BEGIN_MSG.as_bytes())
}

/// Print human-readable signature verification result.
fn print_sig_status(status: SigStatus) {
    match status {
        SigStatus::NoSignature => {}
        SigStatus::Verified => eprintln!("[sig] VERIFIED"),
        SigStatus::Invalid => eprintln!("[sig] INVALID"),
        SigStatus::Unexpected => eprintln!("[sig] signature expected but missing/invalid"),
    }
}

/// Print a simple progress indicator with throughput statistics.
fn print_progress(label: &str, processed: u64, total: u64, elapsed: std::time::Duration) {
    let pct = (processed as f64 / total as f64) * 100.0;
    let mib = processed as f64 / (1 << 20) as f64;
    let total_mib = total as f64 / (1 << 20) as f64;
    let secs = elapsed.as_secs_f64();
    let speed = if secs > 0.0 {
        mib / secs
    } else {
        0.0
    };

    eprint!(
        "\r[{}] {:.1}% | {:.1} MiB / {:.1} MiB | {:.1} MiB/s",
        label, pct, mib, total_mib, speed
    );
    let _ = io::stderr().flush();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let stdout_is_tty = std::io::stdout().is_terminal();

    match cli.command {
        Command::Keygen {
            out_pub,
            out_sec,
            mut pass,
        } => {
            if pass.is_none() {
                pass = Some(prompt_hidden("Passphrase for secret key")?);
            }
            let pass = pass.unwrap();
            let (pub_armor, sec_armor) =
                generate_keypair(&pass).map_err(|()| anyhow!("Key generation failed"))?;

            match &out_pub {
                Some(p) => fs::write(p, &pub_armor)
                    .with_context(|| format!("Cannot write PUBLIC key: {}", p.display()))?,
                None => {
                    if out_sec.is_some() {
                        println!("{}", pub_armor);
                    }
                }
            }

            match &out_sec {
                Some(p) => fs::write(p, &sec_armor)
                    .with_context(|| format!("Cannot write SECRET key: {}", p.display()))?,
                None => {
                    if out_pub.is_some() {
                        println!("{}", sec_armor);
                    } else {
                        println!("{}", pub_armor);
                        println!();
                        println!("{}", sec_armor);
                    }
                }
            }
        }

        Command::Encrypt {
            input,
            output,
            recipient,
            signer_secret,
            mut signer_pass,
            stream,
            chunk_size,
            armor,
            allow_many_recipients,
        } => {
            let recip_count = recipient.len();
            if recip_count == 0 {
                bail!("At least one recipient key (-r) is required");
            }
            if recip_count > RECIP_HARD_LIMIT && !allow_many_recipients {
                bail!(
                    "Too many recipients: {} (limit: {}).\n\
                     If you really intend to encrypt for this many recipients, \
                     re-run with --allow-many-recipients.",
                    recip_count,
                    RECIP_HARD_LIMIT
                );
            }

            let recips = recipient
                .into_iter()
                .map(|p| {
                    fs::read_to_string(&p)
                        .with_context(|| format!("Cannot read recipient key: {}", p.display()))
                })
                .collect::<Result<Vec<_>>>()?
                .join("\n");

            if stream {
                if armor {
                    bail!("--stream does not support --armor");
                }
                if output == "-" && stdout_is_tty {
                    bail!(
                        "Refusing to write raw binary streaming ciphertext to the terminal.\n\
                         Use -o FILE, or pipe the output to another program (e.g. -o - | velum decrypt ...)."
                    );
                }

                // Validate chunk size
                if let Some(size) = chunk_size {
                    if size > MAX_SAFE_CHUNK_SIZE {
                        bail!(
                            "Chunk size {} bytes exceeds maximum allowed size of {} bytes (~4 GB).\n\
                             This limit prevents frame length collision with the streaming trailer sentinel.",
                            size,
                            MAX_SAFE_CHUNK_SIZE
                        );
                    }
                    if size < MIN_RECOMMENDED_CHUNK_SIZE {
                        eprintln!(
                            "⚠ Warning: Chunk size {} bytes is below the recommended minimum of {} bytes (64 KiB).",
                            size,
                            MIN_RECOMMENDED_CHUNK_SIZE
                        );
                        eprintln!("  Small chunks significantly reduce throughput and increase overhead.");
                    }
                }

                let total_bytes = if input == "-" {
                    None
                } else {
                    fs::metadata(&input).ok().map(|m| m.len())
                };

                let signer = signer_secret
                    .map(|p| -> Result<_> {
                        if signer_pass.is_none() {
                            signer_pass = Some(prompt_hidden("Signer passphrase")?);
                        }
                        let pass = signer_pass.as_ref().unwrap();
                        let sec = fs::read_to_string(&p)?;
                        Ok((sec, pass.clone()))
                    })
                    .transpose()?;

                if output == "-" {
                    let mut infile: Box<dyn Read> = if input == "-" {
                        Box::new(io::stdin().lock())
                    } else {
                        Box::new(File::open(&input)?)
                    };
                    let mut stdout = io::stdout().lock();
                    encrypt_file_stream(
                        &mut infile,
                        &mut stdout,
                        &recips,
                        signer.as_ref().map(|(s, p)| (s.as_str(), p.as_str())),
                        chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
                    )
                    .map_err(|()| anyhow!("Streaming encryption failed"))?;
                } else {
                    let start = Instant::now();
                    let infile: Box<dyn Read> = if input == "-" {
                        Box::new(io::stdin().lock())
                    } else {
                        Box::new(File::open(&input)?)
                    };
                    let mut outfile = File::create(&output)?;

                    let should_show_progress = total_bytes.is_some() && total_bytes.unwrap() > 0;

                    struct ProgressReader<R> {
                        inner: R,
                        processed: u64,
                        total: u64,
                        start: Instant,
                    }

                    impl<R: Read> Read for ProgressReader<R> {
                        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                            let n = self.inner.read(buf)?;
                            if n > 0 {
                                self.processed += n as u64;
                                if self.total > 0 {
                                    print_progress("enc", self.processed, self.total, self.start.elapsed());
                                }
                            }
                            Ok(n)
                        }
                    }

                    if should_show_progress {
                        let mut progress_in = ProgressReader {
                            inner: infile,
                            processed: 0,
                            total: total_bytes.unwrap(),
                            start,
                        };

                        encrypt_file_stream(
                            &mut progress_in,
                            &mut outfile,
                            &recips,
                            signer.as_ref().map(|(s, p)| (s.as_str(), p.as_str())),
                            chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
                        )
                        .map_err(|()| anyhow!("Streaming encryption failed"))?;
                        eprintln!();
                    } else {
                        let mut infile = infile;
                        encrypt_file_stream(
                            &mut infile,
                            &mut outfile,
                            &recips,
                            signer.as_ref().map(|(s, p)| (s.as_str(), p.as_str())),
                            chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
                        )
                        .map_err(|()| anyhow!("Streaming encryption failed"))?;
                    }
                }
            } else {
                let pt = read_all(&input)?;
                let signer = signer_secret
                    .map(|p| -> Result<_> {
                        if signer_pass.is_none() {
                            signer_pass = Some(prompt_hidden("Signer passphrase")?);
                        }
                        let pass = signer_pass.as_ref().unwrap();
                        let sec = fs::read_to_string(&p)?;
                        Ok((sec, pass.clone()))
                    })
                    .transpose()?;

                if armor {
                    let ct = encrypt(
                        &pt,
                        &recips,
                        signer.as_ref().map(|(s, p)| (s.as_str(), p.as_str())),
                    )
                    .map_err(|()| anyhow!("Encryption failed"))?;
                    write_all(&output, &ct)?;
                } else {
                    let ct = encrypt_binary(
                        &pt,
                        &recips,
                        signer.as_ref().map(|(s, p)| (s.as_str(), p.as_str())),
                    )
                    .map_err(|()| anyhow!("Encryption failed"))?;
                    write_all(&output, &ct)?;
                }
            }
        }

        Command::Decrypt {
            input,
            output,
            secret,
            mut pass,
            expect_public,
            armor_input,
            binary_input,
        } => {
            if pass.is_none() {
                pass = Some(prompt_hidden("Passphrase")?);
            }
            let pass = pass.unwrap();
            let my_secret = fs::read_to_string(&secret)
                .with_context(|| format!("Cannot read secret key: {}", secret.display()))?;

            let expected_pub = if let Some(p) = expect_public {
                Some(fs::read_to_string(&p)?)
            } else {
                None
            };

            // Forced format paths
            if armor_input {
                let data = read_all(&input)?;
                let (pt, status_i32) = decrypt(&data, &my_secret, &pass, expected_pub.as_deref())
                    .map_err(|()| anyhow!("Decryption failed"))?;
                print_sig_status(status_i32.into());
                write_all(&output, &pt)?;
                return Ok(());
            }

            if binary_input {
                let start = Instant::now();
                if input == "-" {
                    let mut stdin_lock = io::stdin().lock();
                    if output == "-" {
                        let mut stdout = io::stdout().lock();
                        let mut sink = |chunk: &[u8]| {
                            match stdout.write_all(chunk) {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                                Err(_) => Err(()),
                            }
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut stdin_lock,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        print_sig_status(status_i32.into());
                    } else {
                        let mut outfile = File::create(&output)?;
                        let mut sink = |chunk: &[u8]| {
                            outfile.write_all(chunk).map_err(|_| ())?;
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut stdin_lock,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        print_sig_status(status_i32.into());
                    }
                } else {
                    let mut file = File::open(&input)?;
                    let total_bytes = file.metadata()?.len();
                    if output == "-" {
                        let mut stdout = io::stdout().lock();
                        let mut processed: u64 = 0;
                        let mut sink = |chunk: &[u8]| {
                            match stdout.write_all(chunk) {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                                Err(_) => Err(()),
                            }?;
                            processed += chunk.len() as u64;
                            if total_bytes > 0 {
                                print_progress("dec", processed, total_bytes, start.elapsed());
                            }
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut file,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        eprintln!();
                        print_sig_status(status_i32.into());
                    } else {
                        let mut outfile = File::create(&output)?;
                        let mut processed: u64 = 0;
                        let mut sink = |chunk: &[u8]| {
                            outfile.write_all(chunk).map_err(|_| ())?;
                            processed += chunk.len() as u64;
                            if total_bytes > 0 {
                                print_progress("dec", processed, total_bytes, start.elapsed());
                            }
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut file,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        eprintln!();
                        print_sig_status(status_i32.into());
                    }
                }
                return Ok(());
            }

            // Auto-detect input format
            if input == "-" {
                let mut stdin_lock = io::stdin().lock();
                let mut peek = vec![0u8; 64];
                let n = stdin_lock.read(&mut peek)?;
                peek.truncate(n);

                if is_armored(&peek[..]) {
                    let mut rest = Vec::new();
                    stdin_lock.read_to_end(&mut rest)?;
                    peek.extend_from_slice(&rest);
                    let (pt, status_i32) = decrypt(&peek, &my_secret, &pass, expected_pub.as_deref())
                        .map_err(|()| anyhow!("Decryption failed"))?;
                    print_sig_status(status_i32.into());
                    write_all(&output, &pt)?;
                } else {
                    let chained = io::Cursor::new(peek).chain(stdin_lock);
                    let mut reader = chained;
                    if output == "-" {
                        let mut stdout = io::stdout().lock();
                        let mut sink = |chunk: &[u8]| {
                            match stdout.write_all(chunk) {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                                Err(_) => Err(()),
                            }
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut reader,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        print_sig_status(status_i32.into());
                    } else {
                        let mut outfile = File::create(&output)?;
                        let mut sink = |chunk: &[u8]| {
                            outfile.write_all(chunk).map_err(|_| ())?;
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut reader,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        print_sig_status(status_i32.into());
                    }
                }
            } else {
                let mut file = File::open(&input)?;
                let total_bytes = file.metadata()?.len();
                let mut peek = [0u8; 64];
                let n = file.read(&mut peek)?;
                file.seek(SeekFrom::Start(0))?;

                if is_armored(&peek[..n]) {
                    let data = read_all(&input)?;
                    let (pt, status_i32) = decrypt(&data, &my_secret, &pass, expected_pub.as_deref())
                        .map_err(|()| anyhow!("Decryption failed"))?;
                    print_sig_status(status_i32.into());
                    write_all(&output, &pt)?;
                } else {
                    let start = Instant::now();
                    if output == "-" {
                        let mut stdout = io::stdout().lock();
                        let mut processed: u64 = 0;
                        let mut sink = |chunk: &[u8]| {
                            match stdout.write_all(chunk) {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                                Err(_) => Err(()),
                            }?;
                            processed += chunk.len() as u64;
                            if total_bytes > 0 {
                                print_progress("dec", processed, total_bytes, start.elapsed());
                            }
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut file,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        eprintln!();
                        print_sig_status(status_i32.into());
                    } else {
                        let mut outfile = File::create(&output)?;
                        let mut processed: u64 = 0;
                        let mut sink = |chunk: &[u8]| {
                            outfile.write_all(chunk).map_err(|_| ())?;
                            processed += chunk.len() as u64;
                            if total_bytes > 0 {
                                print_progress("dec", processed, total_bytes, start.elapsed());
                            }
                            Ok(())
                        };
                        let status_i32 = decrypt_file_stream(
                            &mut file,
                            &my_secret,
                            &pass,
                            expected_pub.as_deref(),
                            &mut sink,
                        )
                        .map_err(|()| anyhow!("Streaming decryption failed"))?;
                        eprintln!();
                        print_sig_status(status_i32.into());
                    }
                }
            }
        }

        Command::Rewrap {
            input_secret,
            output,
            mut old_pass,
            mut new_pass,
            m_mib,
            t_cost,
            parallelism,
        } => {
            if old_pass.is_none() {
                old_pass = Some(prompt_hidden("Old passphrase")?);
            }
            if new_pass.is_none() {
                new_pass = Some(prompt_hidden("New passphrase")?);
            }
            let old_pass = old_pass.unwrap();
            let new_pass = new_pass.unwrap();
            let old_armor = fs::read_to_string(&input_secret)?;
            let new_armor = rewrap_secret_with_params(
                &old_armor,
                &old_pass,
                &new_pass,
                m_mib.unwrap_or(96) * 1024,
                t_cost.unwrap_or(4),
                parallelism.unwrap_or(4),
            )
            .map_err(|()| anyhow!("Password change failed"))?;
            write_all(&output, new_armor.as_bytes())?;
        }
    }

    Ok(())
}
