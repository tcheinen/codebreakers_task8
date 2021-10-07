use cipher::consts::U64;
use cipher::generic_array::ArrayLength;
use hex_literal::hex;
use itertools::Itertools;
use primitive_types::{U256, U512};
use rayon::prelude::*;
use salsa20::cipher::generic_array::GenericArray;
use salsa20::{hsalsa20, Core, Key, Nonce, XNonce, R8};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead};
use std::io::{BufReader, Write};
use std::sync::atomic::AtomicU32;
use std::sync::mpsc::{channel, Sender};
pub fn increment_bytearray(arr: &mut [u64; 4]) {
    let mut should_overflow = 1;
    for i in 0..4 {
        let (next, overflow) = unsafe { arr.get_unchecked(i) }.overflowing_add(should_overflow);
        unsafe {
            *arr.get_unchecked_mut(i) = next;
        };
        if overflow {
            should_overflow = 1;
        } else {
            return;
        }
    }
}

const INCREMENT: u32 = 0xffffff;
const THREADS: usize = 5;
#[derive(Debug)]
enum TrialResult {
    KeyFound(U256),
    Exhausted(U256),
}

fn try_slice(start: U256, sender: Sender<TrialResult>) {
    let TARGET_u16: [u16; 7] = unsafe { std::mem::transmute(hex!("6114421FE3B633D82A11876CEB70")) };
    let mut trial_key = unsafe { std::mem::transmute::<U256, [u64; 4]>(start) };
    let nonce = XNonce::from_slice(&hex!("03aafca06d705624d7e2a9dd9a0fc49c08624272603dbddb"));
    let mut padded_nonce = Nonce::default();
    padded_nonce.copy_from_slice(&nonce[16..]);
    let mut output = [0u8; 64];
    for i in 0..INCREMENT {
        let key: Key =
            GenericArray::from(unsafe { std::mem::transmute::<[u64; 4], [u8; 32]>(trial_key) });
        let mut subkey = hsalsa20(&key, nonce[..16].as_ref().into());

        let mut core = Core::<R8>::new(&subkey, &padded_nonce);
        core.generate(&mut output);
        increment_bytearray(&mut trial_key);
        let output_u16: &[u16] = unsafe { std::mem::transmute(&output[..14]) };
        if (0..7).all(|x| TARGET_u16[x] == output_u16[x]) {
            sender.send(TrialResult::KeyFound(unsafe {
                std::mem::transmute::<[u64; 4], U256>(trial_key)
            }));
            return;
        }
    }
    sender.send(TrialResult::Exhausted(start));
}

fn warmup() -> U256 {
    let mut processed = {
        let mut log = OpenOptions::new().read(true).open("run.log").unwrap();
        let log_reader = BufReader::new(log);
        log_reader
            .lines()
            .flat_map(|x| x.ok()?.split("/").next().map(str::to_owned))
            .flat_map(|x| U256::from_dec_str(&x))
            .collect_vec()
    };

    dmsort::sort(&mut processed);
    processed.dedup(); // i have no idea if it matters lol
    // let mut log = OpenOptions::new().write(true).truncate(true).open("run.log").unwrap();
    let mut counter = U256::from(0);
    for i in processed.into_iter().skip(1) {
        // println!("{} = {}", counter + U256::from(INCREMENT), i);
        if counter + U256::from(INCREMENT) != i {
            return counter;
        };
        // writeln!(&mut log, "{}/{}", counter, U256::MAX);
        counter += U256::from(INCREMENT)
    }
    counter
}

fn main() {
    print!("warming up...");
    let mut current = warmup();
    println!("done");
    println!("starting at n = {}", current);
    // std::process::exit(0);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .unwrap();
    let (sender, receiver) = channel();

    for i in 0..THREADS {
        let sender2 = sender.clone();
        pool.spawn(move || try_slice(current, sender2));
        current += U256::from(INCREMENT);
    }
    let mut log = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("run.log")
        .unwrap();
    while let Ok(message) = receiver.recv() {
        let child_sender = sender.clone();
        pool.spawn(move || try_slice(current, child_sender));
        current += U256::from(INCREMENT);
        match message {
            TrialResult::Exhausted(num) => {
                writeln!(&mut log, "{}/{}", num, U256::MAX);
            }
            TrialResult::KeyFound(num) => {
                writeln!(&mut log, "found at {:?}", num);
                std::process::exit(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use primitive_types::U256;

    #[test]
    fn test_add_1_to_0() {
        let mut init = U256::from(0);
        let mut target = U256::from(1);
        increment_bytearray(unsafe { std::mem::transmute::<&mut U256, &mut [u8; 32]>(&mut init) });
        assert_eq!(init, target);
    }
    #[test]
    fn test_add_1_to_255() {
        let mut init = U256::from(255);
        let mut target = U256::from(256);
        increment_bytearray(unsafe { std::mem::transmute::<&mut U256, &mut [u8; 32]>(&mut init) });
        assert_eq!(init, target);
    }

    #[test]
    fn test_add_1_to_0xffffff() {
        let mut init = U256::from(0xffffff);
        let mut target = U256::from(0xffffff + 1);
        increment_bytearray(unsafe { std::mem::transmute::<&mut U256, &mut [u8; 32]>(&mut init) });
        assert_eq!(init, target);
    }
}
