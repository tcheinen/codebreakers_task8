use itertools::Itertools;
use std::fmt::Write;
use numtoa::NumToA;
use hex_literal::hex;
use sha2::{Sha256, Digest};
use std::cell::UnsafeCell;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};
const ciphertexts: [[u8; 78]; 1] = [hex!("3a18c632509b738a6811818dd96f30e271fa033c675aff0b015aa78bea4ca7ca99ba2f738db7def7483574f1f9d221e643ada5b59f792d10a77ae66a9c4980ec3a270c4af001ceca31921acd25d1")];
unsafe fn mutate(name_buf: &[u8]) {
    let mut buf: [u8; 32] = [0u8; 32];
    // let mut session_key = "A+2.1.3.0+1609480800".as_bytes_mut();
    // let mut session_key = hex!("412b322e312e332e302b313630393438303830300000");
    // let mut buf2 = buf.get_mut();
    let session_key = {
        {
            let (name, rem) = buf.split_at_mut(name_buf.len());
            let (version, rem) = rem.split_at_mut(9);
            let (time, rem) = rem.split_at_mut(11);
            name.copy_from_slice(name_buf);
            version.copy_from_slice("+2.1.3.0+".as_bytes());
            // println!("{:?}", version);

        }
        let (session_key, _) = buf.split_at_mut(name_buf.len() + 9 + 10);
        session_key
    };
    // 1609480800..1633669093
    for i in 1633710083..1633710083+1 { // 2021/01/01 to 2021/10/08 (today)

        i.numtoa(10, &mut session_key[name_buf.len()+8..name_buf.len()+9+10]);
        println!("{:?}", String::from_utf8_lossy(&session_key));
        let mut hasher = Sha256::new();
        let hash = Sha256::digest(&session_key);
        // sodium_oxide::crypto::secretbox::xsalsa20poly1305::open
        // use first 24 bytes as nonce
        // use remainder as ciphertext
        // use hash as key?
        // brrr
        println!("{:x?}", &hash);
        let key = Key::from_slice(&hash).expect("lmao invalid key");
        for data in ciphertexts {
            let nonce = Nonce::from_slice(&data[..24]).expect("lmao invalid nonce");
            let cipher = &data[24..];
            println!("{:x?}", cipher);
            if let Ok(inner) = sodiumoxide::crypto::secretbox::xsalsa20poly1305::open(cipher, &nonce, &key) {
                println!("{:?}", inner);
                panic!("oops")
            }
        }
        // println!("{:?}", hash);
        // println!("{}", std::mem::transmute::<&[u8], &str>(time))
        // this is degenerate
    }
}

fn main() {

    // let decrypt = hex!("ce1f322befe0182c8ce74930906c46303be3e0c40e48933a84533d33854a6cf5f36a0eafba0c2516932afb607bba554c409127da6fffef158e0a9bd29f341ba56a39c76fc058131d589312030c78");
    // // format is known to be sky+2.1.3.0+time
    // 0x7ffff7806430:	0xb7	0xd5	0x87	0x5b	0xc5	0x1f	0x5f	0x52
    // 0x7ffff7806438:	0x28	0xb5	0xb6	0x7f	0xbf	0xe8	0xfc	0x26
    // 0x7ffff7806440:	0x6e	0xc2	0xd0	0x29	0x5	0xf7	0x3a	0x8c
    // 0x7ffff7806448:	0x86	0x2c	0xd	0xa0	0x4d	0x84	0x7e	0x71
    let KNOWN = "sky+2.1.3.0+1633710083";
    unsafe {
        mutate(&hex!("736b79"));
    }
}