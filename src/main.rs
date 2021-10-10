use hex_literal::hex;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use itertools::iproduct;
use itertools::Itertools;
use numtoa::NumToA;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};
use std::fs::OpenOptions;

struct Ciphertext {
    start: usize,
    end: usize,
    data: [u8; 78],
}

const CIPHERTEXTS: [Ciphertext; 3] = [
    Ciphertext {
        start:1615896094 - 5,
        end: 1615896094,
        data: hex!("3e89c1c19521e7a02005ad47330a19b2e59af71dacbc0c935f6d3e150c9d095882d4c5b29dc7c3aea646563111e88d9ffdb5a8b412f4750d9d01091c4868c344ea35122b5c0353253eb1c4585ffb")
    },
    Ciphertext {
        start: 1615896116 - 5,
        end: 1615896116,
        data: hex!("d4522bf8f4f1cfae978f250cc9540ac39ea3ce767ec431224153136c3f1a3b9582b955598297e0edcd68ec7fb27461f1be66d1ffbb40b548b068d05d5d3d20842dc7b73259421c6f2eef2f0a844e")
    },
    Ciphertext {
        start: 1615896139 - 5,
        end: 1615896139,
        data: hex!("95146b362d2ca484e608308547dbeed8af8ce7bbc00ffdf92bc572d6bd4f0d7210b647a2cadacba9d2870101d854cc78ee340ca9f0ea277e34bbdb4badc969de55fd348ae7b746b5b0c023dbad70")
    },
];

#[inline(always)]
unsafe fn brute_range(
    name_in: &str,
    version_in: &str,
    ciphertexts: &[Ciphertext],
) -> Vec<(String, [u8; 78], Vec<u8>)> {
    let mut buf: [u8; 72] = [0u8; 72];
    let mut results: Vec<(String, [u8; 78], Vec<u8>)> = Vec::new();
    let session_key = {
        buf[..name_in.len()].copy_from_slice(name_in.as_bytes());
        buf[name_in.len()] = b'+';
        buf[name_in.len() + version_in.len() + 1] = b'+';
        buf[name_in.len() + 1..name_in.len() + version_in.len() + 1]
            .copy_from_slice(version_in.as_bytes());
        let (session_key, _) = buf.split_at_mut(name_in.len() + 9 + 10);
        session_key
    };
    // println!("{:?}", String::from_utf8_lossy(session_key));

    for ciphertext in ciphertexts {
        for i in ciphertext.start..ciphertext.end {
            (i as u32).numtoa(
                10,
                &mut session_key[name_in.len() + 8..name_in.len() + 9 + 10],
            );
            // println!("{:?}", String::from_utf8_lossy(session_key));
            let hash = Sha256::digest(&session_key[..name_in.len() + 9 + 10]);
            let key = Key::from_slice(&hash).expect("lmao invalid key");
            let nonce = Nonce::from_slice(&ciphertext.data[4..28]).expect("lmao invalid nonce");
            let cipher = &ciphertext.data[28..];
            if let Ok(inner) =
                sodiumoxide::crypto::secretbox::xsalsa20poly1305::open(cipher, &nonce, &key)
            {
                results.push((
                    String::from_utf8_lossy(&session_key[..name_in.len() + 9 + 10]).to_string(),
                    ciphertext.data.clone(),
                    inner,
                ));
            }
        }
    }
    results
}

const LOWER: u8 = 0x61;
const UPPER: u8 = 0x7a;
const RANGE: std::ops::RangeInclusive<u8> = LOWER..=UPPER;

const NAME_LEN: usize = 6;
const CHUNK_SIZE: usize = 100;
// fn brute_name() {
//     let pool = rayon::ThreadPoolBuilder::new()
//         .num_threads(4)
//         .build()
//         .unwrap();
//     pool.install(|| {
//     let pb = ProgressBar::new((RANGE.size_hint().0.pow(NAME_LEN as u32)) as u64);
//     pb.set_style(
//         ProgressStyle::default_bar()
//             .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})")
//             .with_key("eta", |state| {
//                 format!(
//                     "{}::{}::{}",
//                     (state.eta().as_secs() / 60 / 60) % 60,
//                     (state.eta().as_secs() / 60) % 60,
//                     state.eta().as_secs() % 60,
//                 )
//             }),
//     );
//     pb.set_draw_delta(100);
//
//     RANGE
//         .cartesian_power(NAME_LEN)
//         .into_iter()
//         .par_bridge()
//         .progress_with(pb)
//         .for_each(|name| {
//             let mut buf = [0u8; NAME_LEN];
//             buf.copy_from_slice(name.as_slice());
//             for (session_key, session, plaintext) in
//                 unsafe { brute_range(std::mem::transmute(buf.as_slice()), "2.1.3.0", &CIPHERTEXTS) }
//             {
//                 println!(
//                     "decrypted {} with a session key of {} for a plaintext of {}",
//                     &hex::encode(session),
//                     session_key,
//                     &hex::encode(plaintext)
//                 );
//             }
//         });
//     });
// }

fn brute_versions() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(72)
        .build()
        .unwrap();
    pool.install(|| {
        let names_str = std::fs::read_to_string("names_staged.txt").unwrap();
        let versions_str = std::fs::read_to_string("versions.txt").unwrap();
        let pb = ProgressBar::new((names_str.chars().filter(|x| x == &'\n').count() * versions_str.chars().filter(|x| x == &'\n').count()) as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})")
                .progress_chars("#>-")
                .with_key("eta", |state| {
                    format!(
                        "{}::{}::{}",
                        (state.eta().as_secs() / 60 / 60) % 60,
                        (state.eta().as_secs() / 60) % 60,
                        state.eta().as_secs() % 60,
                    )
                }),
        );
        pb.set_draw_delta(10000);


        let names = names_str
            .split("\n")
            .map(|x| x.trim_end());
        let versions = versions_str
            .split("\n")
            .map(|x| x.trim_end());


    iproduct!(names, versions)
        .par_bridge()
        .progress_with(pb)
        .for_each(|(name, version)| {
            use std::io::Write;
            for (session_key, session, plaintext) in
                unsafe { brute_range(name, version, &CIPHERTEXTS) }
            {
                let mut log = OpenOptions::new().write(true).append(true).open("decrypted.log").unwrap();
                writeln!(
                    &mut log,
                    "decrypted {} with a session key of {} for a plaintext of {}",
                    &hex::encode(session),
                    session_key,
                    &hex::encode(plaintext)
                );
            }
        });
    });
}
fn main() {
    brute_versions();
}
// fn main() {
//     let pool = rayon::ThreadPoolBuilder::new()
//         .num_threads(4)
//         .build()
//         .unwrap();
//
//     pool.install(|| {
//         let decryption_log = Arc::new(Mutex::new(
//             std::fs::OpenOptions::new()
//                 .create(true)
//                 .append(true)
//                 .open("decrypted.log")
//                 .expect("couldn't create decryption log"),
//         ));
//         let mut name_buf = [0u8; 32];
//         let pb = ProgressBar::new(((UPPER - LOWER) as u64).pow(NAME_LEN));
//         pb.set_style(
//             ProgressStyle::default_bar()
//                 .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
//                 .with_key("eta", |state| {
//                     format!(
//                         "{}::{}::{}",
//                         (state.eta().as_secs() / 60 / 60) % 60,
//                         (state.eta().as_secs() / 60) % 60,
//                         state.eta().as_secs() % 60,
//                     )
//                 }),
//         );
//
//         unsafe {
//             // // try_name("AA".as_bytes());
//             // RANGE
//             //     .combinations_with_replacement(NAME_LEN as usize)
//             include_str!("../malenames-usa-top1000.txt")
//                 .split('\n')
//                 .map(|x| x.trim_end())
//                 .map(|x| x.as_bytes())
//                 .par_bridge()
//                 .progress_with(pb)
//                 .for_each(|b0| {
//                     // let mut buf2 = name_buf.clone();
//
//                     // buf2[..b0.len()].copy_from_slice(b0);
//                     for (session_key, session, plaintext) in try_name(b0) {
//                         let mut log = decryption_log.lock().expect("locked mutex");
//                         writeln!(
//                             &mut log,
//                             "decrypted {} with a session key of {} for a plaintext of {}",
//                             &hex::encode(session),
//                             session_key,
//                             &hex::encode(plaintext)
//                         );
//                     }
//                 });
//         }
//         println!("done :)");
//         // pb.finish_with_message("done");
//     });
// }

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};

    #[test]
    fn sanity_check() {
        let session_key = "sky+2.1.3.0+1633714191".as_bytes();
        let control_hash = hex!("1c62b7cc293dda7515b73d2591e0256f8429ed6e3d2d2379ac70f971c29d5ec1");
        let control_message =
            hex!("19b0a81d4d00000200024d080010e81efb2bd4bff29a5b81364b3b635430eda9f5ce");
        let control_nonce = hex!("a9d810288ca8b09c05628f538447078f981921154cc44a62");
        let control_ciphertext = hex!("f5080b42a9d810288ca8b09c05628f538447078f981921154cc44a6277dd971e105a01f551bc84d165ef0c77365448852c5b1d3a03c42fb6d1d6ac2d1f7fb0522766b39b3ce34015384995c6deaa");
        assert_eq!(control_hash, Sha256::digest(session_key).as_slice());
        assert_eq!(
            &control_ciphertext[28..],
            sodiumoxide::crypto::secretbox::xsalsa20poly1305::seal(
                &control_message,
                &Nonce::from_slice(&control_nonce).unwrap(),
                &Key::from_slice(&control_hash).unwrap()
            )
            .as_slice()
        );
        assert_eq!(
            &control_message,
            sodiumoxide::crypto::secretbox::xsalsa20poly1305::open(
                &control_ciphertext[28..],
                &Nonce::from_slice(&control_ciphertext[4..28]).unwrap(),
                &Key::from_slice(&control_hash).unwrap()
            )
            .unwrap()
            .as_slice()
        );
        // 1. hash session key and assert equality with known hash
        // 2. encrypt message and assert equality to known ciphertext
        // 3. decrypt ciphertext and assert equality to known message
    }

    #[test]
    fn try_with_own() {
        let session_key_known = "sky+2.1.3.0+1633714191";
        let control_message =
            hex!("19b0a81d4d00000200024d080010e81efb2bd4bff29a5b81364b3b635430eda9f5ce");
        let control_ciphertext = hex!("f5080b42a9d810288ca8b09c05628f538447078f981921154cc44a6277dd971e105a01f551bc84d165ef0c77365448852c5b1d3a03c42fb6d1d6ac2d1f7fb0522766b39b3ce34015384995c6deaa");
        let res = unsafe {
            brute_range(
                "sky",
                "2.1.3.0",
                &[Ciphertext {
                    start: 1633714191,
                    end: 1633714191 + 1,
                    data: control_ciphertext,
                }],
            )
        };
        assert_eq!(res[0].0, session_key_known);
        assert_eq!(res[0].2, control_message);
    }

    #[test]
    fn try_with_first_decrypted() {
        let session_key_known = "root+2.1.3.0+1615896089";
        let control_message =
            hex!("19b0a81d4d00000200024d080010c2cd31ed27134010a0dedfc817a341b7eda9f5ce");
        let control_ciphertext = hex!("f28d0dbdc78000004088aa3c33e18665170003436298a84997dcec6f6e2ae32d3622c39ae24f47a6c510ab97ec2cf61c10d23aaadd2a0bdfd0fe1bec1a1483289e16abd25e348039c793584e01e9");
        let res = unsafe {
            brute_range(
                "root",
                "2.1.3.0",
                &[Ciphertext {
                    start: 1615896089,
                    end: 1615896089 + 1,
                    data: control_ciphertext,
                }],
            )
        };
        assert_eq!(res[0].0, session_key_known);
        assert_eq!(res[0].2, control_message);
    }

    #[test]
    fn decrypt_claris() {
        let session_key_known = "claris+1.3.7.7+1615896045";
        let control_message =
            hex!("19b0a81d4d00000200024d0800101b2522dbd2c942dc8830e53dc7e9b7f8eda9f5ce");
        let control_ciphertext = hex!("03aafca06d705624d7e2a9dd9a0fc49c08624272603dbddb78a4ea02aeb633da2a13ca64eb60aa2787e03357c37c95190934098bdcaf88f39cc5d7d4e81181d2d8ee6a7761815633dcae8de8c3e0");
        let res = unsafe {
            brute_range(
                "claris",
                "1.3.7.7",
                &[Ciphertext {
                    start: 1615896045,
                    end: 1615896045 + 1,
                    data: control_ciphertext,
                }],
            )
        };
        assert_eq!(res[0].0, session_key_known);
        assert_eq!(res[0].2, control_message);
    }

    #[test]
    fn decrypt_nonie() {
        let session_key_known = "nonie+0.2.0.0+1615896077";
        let control_message =
            hex!("19b0a81d4d00000200024d08001008d8cf0b62364dd18f81bc08ca5c8c4deda9f5ce");
        let control_ciphertext = hex!("88287822ae3ccbb7159cd8e1b5f8ff1a2347d2d89e97ea916ebe76369193f5f01c1b7e753220f4388355b73781938f7efd742954db8ead7474465e869ed9751ff86e5870829432c0bb0fadc441c6");
        let res = unsafe {
            brute_range(
                "nonie",
                "0.2.0.0",
                &[Ciphertext {
                    start: 1615896077,
                    end: 1615896077 + 1,
                    data: control_ciphertext,
                }],
            )
        };
        assert_eq!(res[0].0, session_key_known);
        assert_eq!(res[0].2, control_message);
    }
}