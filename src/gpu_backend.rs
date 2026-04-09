use crate::backend::CrackingBackend;
use crate::cpu_backend::CpuBackend;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use opencl3::command_queue::{CommandQueue, CL_QUEUE_PROFILING_ENABLE};
use opencl3::context::Context;
use opencl3::device::{Device, get_all_devices, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_WRITE_ONLY};
use opencl3::program::Program;
use opencl3::types::{cl_event, CL_BLOCKING, CL_NON_BLOCKING};
use std::ptr;
use std::time::Instant;

const MD5_KERNEL_SOURCE: &str = include_str!("kernels/md5.cl");
const SHA1_KERNEL_SOURCE: &str = include_str!("kernels/sha1.cl");
const SHA256_KERNEL_SOURCE: &str = include_str!("kernels/sha256.cl");
const SHA512_KERNEL_SOURCE: &str = include_str!("kernels/sha512.cl");
const SHA3_256_KERNEL_SOURCE: &str = include_str!("kernels/sha3_256.cl");
const SHA3_512_KERNEL_SOURCE: &str = include_str!("kernels/sha3_512.cl");
const NTLM_KERNEL_SOURCE: &str = include_str!("kernels/ntlm.cl");

const GPU_SUPPORTED_HEX_TYPES: &[&str] =
    &["md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "ntlm"];

pub struct GpuBackend {
    device: Device,
    context: Context,
    queue: CommandQueue,
}

impl GpuBackend {
    pub fn new() -> Result<Self, String> {
        let device_ids = get_all_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("Failed to query GPU devices: {e}"))?;

        if device_ids.is_empty() {
            return Err(
                "No GPU devices found. Remove --gpu flag to use CPU mode.".to_string(),
            );
        }

        // Select GPU with the most compute units
        let mut best_id = device_ids[0];
        let mut best_cu: u32 = 0;

        for &did in &device_ids {
            let dev = Device::new(did);
            if let Ok(cu) = dev.max_compute_units() {
                if cu > best_cu {
                    best_cu = cu;
                    best_id = did;
                }
            }
        }

        let device = Device::new(best_id);
        let context = Context::from_device(&device)
            .map_err(|e| format!("Failed to create OpenCL context: {e}"))?;
        let queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)
            .map_err(|e| format!("Failed to create command queue: {e}"))?;

        Ok(Self {
            device,
            context,
            queue,
        })
    }

    pub fn print_device_info(&self) {
        let name = self.device.name().unwrap_or_else(|_| "Unknown".into());
        let cu = self.device.max_compute_units().unwrap_or(0);
        let mem_bytes = self.device.global_mem_size().unwrap_or(0);
        let mem_mb = mem_bytes / (1024 * 1024);

        println!(
            " {} GPU: {} | VRAM: {} MB | Compute Units: {}",
            "[*]".green(),
            name.trim().yellow(),
            mem_mb,
            cu
        );
        println!();
    }

    fn gpu_mem_bytes(&self) -> u64 {
        self.device.global_mem_size().unwrap_or(256 * 1024 * 1024)
    }

    /// Generic hash cracking method that works for any algorithm.
    /// All GPU-supported algorithms share the same kernel interface.
    fn crack_hash(
        &self,
        hashes: &[&str],
        wordlist: &str,
        kernel_source: &str,
        kernel_fn_name: &str,
        hex_len: usize,
        digest_size: usize,
        algo_name: &str,
    ) -> usize {
        // Parse target hashes from hex to bytes
        let target_bytes: Vec<Vec<u8>> = hashes
            .iter()
            .filter_map(|h| {
                if h.len() != hex_len {
                    return None;
                }
                let mut bytes = vec![0u8; digest_size];
                faster_hex::hex_decode(h.as_bytes(), &mut bytes).ok()?;
                Some(bytes)
            })
            .collect();

        if target_bytes.is_empty() {
            println!("{} No valid {} hex hashes found", "[!]".red(), algo_name);
            return 0;
        }

        // Flatten targets for GPU upload (contiguous digest_size-byte blocks)
        let target_flat: Vec<u8> = target_bytes
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        let num_targets = target_bytes.len() as u32;

        // Build OpenCL program + kernel
        let program = match Program::create_and_build_from_source(
            &self.context,
            kernel_source,
            "",
        ) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "{} Failed to build {} OpenCL kernel: {e}",
                    "[!]".red(),
                    algo_name
                );
                return 0;
            }
        };

        let kernel = match Kernel::create(&program, kernel_fn_name) {
            Ok(k) => k,
            Err(e) => {
                println!("{} Failed to create kernel: {e}", "[!]".red());
                return 0;
            }
        };

        // Collect words from wordlist
        let words: Vec<&str> = wordlist.lines().collect();
        let total_words = words.len();
        if total_words == 0 {
            return 0;
        }

        // Calculate batch size based on GPU VRAM
        let usable_mem = (self.gpu_mem_bytes() as f64 * 0.70) as usize;
        let target_mem = target_flat.len() + 64;
        let available = usable_mem.saturating_sub(target_mem);
        // Per word: ~avg_word_len bytes data + 4 (offset) + 4 (length) + 4 (result)
        let per_word_estimate: usize = 16 + 4 + 4 + 4;
        let batch_size = (available / per_word_estimate).max(1024).min(total_words);

        // Progress bar
        let bar = ProgressBar::new(total_words as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "\n[{elapsed_precise}] [{bar:40}] {pos}/{len} ({percent}%) {msg}\n",
                )
                .unwrap()
                .progress_chars("=> "),
        );

        let mut found = 0usize;
        let start_time = Instant::now();

        // Process wordlist in VRAM-aware batches
        for batch_start in (0..total_words).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(total_words);
            let batch = &words[batch_start..batch_end];

            // Flatten word data for GPU
            let mut words_data: Vec<u8> = Vec::new();
            let mut offsets: Vec<u32> = Vec::with_capacity(batch.len());
            let mut lengths: Vec<u32> = Vec::with_capacity(batch.len());

            for word in batch {
                offsets.push(words_data.len() as u32);
                lengths.push(word.len() as u32);
                words_data.extend_from_slice(word.as_bytes());
            }

            // OpenCL buffers cannot be zero-sized
            if words_data.is_empty() {
                words_data.push(0);
            }

            match self.execute_hash_batch(
                &kernel,
                &words_data,
                &offsets,
                &lengths,
                batch.len(),
                &target_flat,
                num_targets,
            ) {
                Ok(results) => {
                    for (i, &r) in results.iter().enumerate() {
                        if r != 0xFFFFFFFF {
                            let tidx = r as usize;
                            if tidx < target_bytes.len() {
                                let hex: String = target_bytes[tidx]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                bar.println(format!(
                                    "{} hash cracked {} -> {}",
                                    "[*]".green(),
                                    hex,
                                    batch[i]
                                ));
                                found += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    bar.println(format!("{} GPU batch error: {e}", "[!]".red()));
                }
            }

            bar.inc(batch.len() as u64);

            // Update hash rate in progress bar
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                let hps = bar.position() as f64 / elapsed;
                if hps >= 1_000_000.0 {
                    bar.set_message(format!("{:.2} MH/s", hps / 1_000_000.0));
                } else if hps >= 1_000.0 {
                    bar.set_message(format!("{:.2} KH/s", hps / 1_000.0));
                } else {
                    bar.set_message(format!("{:.2} H/s", hps));
                }
            }
        }

        bar.finish();
        found
    }

    /// Generic GPU batch execution — kernel interface is the same for all algorithms.
    fn execute_hash_batch(
        &self,
        kernel: &Kernel,
        words_data: &[u8],
        offsets: &[u32],
        lengths: &[u32],
        num_words: usize,
        target_flat: &[u8],
        num_targets: u32,
    ) -> Result<Vec<u32>, String> {
        let err = |e: opencl3::error_codes::ClError| format!("OpenCL error: {e}");

        unsafe {
            // Allocate device buffers
            let mut words_buf =
                Buffer::<u8>::create(&self.context, CL_MEM_READ_ONLY, words_data.len(), ptr::null_mut())
                    .map_err(&err)?;
            let mut offsets_buf =
                Buffer::<u32>::create(&self.context, CL_MEM_READ_ONLY, offsets.len(), ptr::null_mut())
                    .map_err(&err)?;
            let mut lengths_buf =
                Buffer::<u32>::create(&self.context, CL_MEM_READ_ONLY, lengths.len(), ptr::null_mut())
                    .map_err(&err)?;
            let mut targets_buf =
                Buffer::<u8>::create(&self.context, CL_MEM_READ_ONLY, target_flat.len(), ptr::null_mut())
                    .map_err(&err)?;
            let results_buf =
                Buffer::<u32>::create(&self.context, CL_MEM_WRITE_ONLY, num_words, ptr::null_mut())
                    .map_err(&err)?;

            // Upload data to GPU (blocking, in-order queue)
            self.queue
                .enqueue_write_buffer(&mut words_buf, CL_BLOCKING, 0, words_data, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut offsets_buf, CL_BLOCKING, 0, offsets, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut lengths_buf, CL_BLOCKING, 0, lengths, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut targets_buf, CL_BLOCKING, 0, target_flat, &[])
                .map_err(&err)?;

            // Dispatch kernel (1 work-item per word)
            let num_words_arg = num_words as u32;
            let kernel_event = ExecuteKernel::new(kernel)
                .set_arg(&words_buf)
                .set_arg(&offsets_buf)
                .set_arg(&lengths_buf)
                .set_arg(&num_words_arg)
                .set_arg(&targets_buf)
                .set_arg(&num_targets)
                .set_arg(&results_buf)
                .set_global_work_size(num_words)
                .enqueue_nd_range(&self.queue)
                .map_err(&err)?;

            // Read results back (blocking read waits for in-order kernel completion)
            let mut results = vec![0xFFFFFFFFu32; num_words];
            let events: Vec<cl_event> = vec![kernel_event.get()];
            let read_event = self
                .queue
                .enqueue_read_buffer(&results_buf, CL_NON_BLOCKING, 0, &mut results, &events)
                .map_err(&err)?;
            read_event.wait().map_err(&err)?;

            Ok(results)
        }
    }
}

impl CrackingBackend for GpuBackend {
    fn run(&self, hashes: &[&str], wordlist: &str, hash_type: &str, rule: bool) -> usize {
        // Memory-hard algorithms: not suited for GPU
        if hash_type == "bcrypt" {
            println!(
                " {} bcrypt is a memory-hard algorithm not suited for GPU acceleration. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        if hash_type == "argon2" {
            println!(
                " {} argon2 is a memory-hard algorithm not suited for GPU acceleration. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Base64 encoded types: GPU supports hex only
        if hash_type.ends_with("-base64") {
            println!(
                " {} GPU acceleration currently supports hex encoding only. '{}' uses base64. Falling back to CPU.",
                "[!]".yellow(),
                hash_type
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Salted types: not yet supported on GPU
        if hash_type.ends_with("-salt") {
            println!(
                " {} GPU acceleration does not yet support salted hashes. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Dual-mode / hybrid types
        if hash_type.contains('/') {
            println!(
                " {} GPU acceleration does not yet support dual-mode types ('{}'). Falling back to CPU.",
                "[!]".yellow(),
                hash_type
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Unsupported hex type
        if !GPU_SUPPORTED_HEX_TYPES.contains(&hash_type) {
            println!(
                " {} GPU acceleration not supported for '{}'. Falling back to CPU.",
                "[!]".yellow(),
                hash_type
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Rules: applied on CPU, GPU dispatch handled in Phase 4
        if rule {
            println!(
                " {} Rules with GPU not yet supported. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        match hash_type {
            "md5" => self.crack_hash(hashes, wordlist, MD5_KERNEL_SOURCE, "md5_crack", 32, 16, "MD5"),
            "sha1" => self.crack_hash(hashes, wordlist, SHA1_KERNEL_SOURCE, "sha1_crack", 40, 20, "SHA1"),
            "sha256" => self.crack_hash(hashes, wordlist, SHA256_KERNEL_SOURCE, "sha256_crack", 64, 32, "SHA256"),
            "sha512" => self.crack_hash(hashes, wordlist, SHA512_KERNEL_SOURCE, "sha512_crack", 128, 64, "SHA512"),
            "sha3-256" => self.crack_hash(hashes, wordlist, SHA3_256_KERNEL_SOURCE, "sha3_256_crack", 64, 32, "SHA3-256"),
            "sha3-512" => self.crack_hash(hashes, wordlist, SHA3_512_KERNEL_SOURCE, "sha3_512_crack", 128, 64, "SHA3-512"),
            "ntlm" => self.crack_hash(hashes, wordlist, NTLM_KERNEL_SOURCE, "ntlm_crack", 32, 16, "NTLM"),
            _ => CpuBackend.run(hashes, wordlist, hash_type, rule),
        }
    }
}
