use rayon::prelude::*;
use std::time::{Duration, Instant};

const DEFAULT_ITERATIONS: usize = 5_000_000;
const WARMUP_ITERATIONS: usize = 50_000;

pub fn run(_gpu: bool) {
    println!("\n[+] Benchmark mode enabled");
    println!("[*] Warming up CPU...\n");

    let input = "benchmark_password";
    warmup(input);

    println!("[*] Starting benchmark...\n");
    println!("[*] Rayon threads: {}", rayon::current_num_threads());
    println!("[*] CPU Threads Available: {}", num_cpus::get());

    println!("\n========== SINGLE THREAD ==========");
    run_single_suite(input, DEFAULT_ITERATIONS);

    println!("\n========== MULTI THREAD (RAYON) ==========");
    run_parallel_suite(input, DEFAULT_ITERATIONS);

    #[cfg(feature = "gpu")]
    if _gpu {
        println!("\n========== GPU (OpenCL) ==========");
        run_gpu_suite(DEFAULT_ITERATIONS);
    }

    println!("\n[+] Benchmark complete\n");
}

fn warmup(input: &str) {
    for _ in 0..WARMUP_ITERATIONS {
        crate::hashes::sha256::crack(input);
    }
}

fn run_single_suite(input: &str, iterations: usize) {
    run_single("MD5", crate::hashes::md5::crack, input, iterations);
    run_single("SHA1", crate::hashes::sha1_hash::crack, input, iterations);
    run_single("SHA256", crate::hashes::sha256::crack, input, iterations);
    run_single("SHA512", crate::hashes::sha512::crack, input, iterations);
    run_single(
        "SHA3-256",
        crate::hashes::sha3_256::crack,
        input,
        iterations,
    );
    run_single(
        "SHA3-512",
        crate::hashes::sha3_512::crack,
        input,
        iterations,
    );
}

fn run_parallel_suite(input: &str, iterations: usize) {
    run_parallel("MD5", crate::hashes::md5::crack, input, iterations);
    run_parallel("SHA1", crate::hashes::sha1_hash::crack, input, iterations);
    run_parallel("SHA256", crate::hashes::sha256::crack, input, iterations);
    run_parallel("SHA512", crate::hashes::sha512::crack, input, iterations);
    run_parallel(
        "SHA3-256",
        crate::hashes::sha3_256::crack,
        input,
        iterations,
    );
    run_parallel(
        "SHA3-512",
        crate::hashes::sha3_512::crack,
        input,
        iterations,
    );
}

fn run_single<F, T>(name: &str, func: F, input: &str, iterations: usize)
where
    F: Fn(&str) -> T,
{
    for _ in 0..10_000 {
        func(input);
    }

    let start = Instant::now();

    for _ in 0..iterations {
        func(input);
    }

    let duration = start.elapsed();
    print_result(name, iterations, duration);
}

fn run_parallel<F, T>(name: &str, func: F, input: &str, iterations: usize)
where
    F: Fn(&str) -> T + Sync + Send,
{
    (0..10_000).into_par_iter().for_each(|_| {
        func(input);
    });

    let start = Instant::now();

    (0..iterations).into_par_iter().for_each(|_| {
        func(input);
    });

    let duration = start.elapsed();
    print_result(name, iterations, duration);
}

fn print_result(name: &str, iterations: usize, duration: Duration) {
    let seconds = duration.as_secs_f64();
    let hps = iterations as f64 / seconds;

    println!("{:<8} | {:>15.2} H/s | {:>10.4} sec", name, hps, seconds);
}

#[cfg(feature = "gpu")]
fn run_gpu_suite(iterations: usize) {
    use crate::gpu_backend::GpuBackend;

    let gpu = match GpuBackend::new() {
        Ok(g) => g,
        Err(e) => {
            println!("[!] GPU benchmark skipped: {}", e);
            return;
        }
    };
    gpu.print_device_info();

    let algos = [
        "md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "ntlm",
    ];
    let names = [
        "MD5", "SHA1", "SHA256", "SHA512", "SHA3-256", "SHA3-512", "NTLM",
    ];

    // Warmup: run a small batch to trigger kernel compilation
    for algo in &algos {
        let _ = gpu.benchmark_algorithm(algo, 10_000);
    }

    for (algo, name) in algos.iter().zip(names.iter()) {
        match gpu.benchmark_algorithm(algo, iterations) {
            Some(duration) => print_result(name, iterations, duration),
            None => println!("{:<8} | FAILED", name),
        }
    }
}
