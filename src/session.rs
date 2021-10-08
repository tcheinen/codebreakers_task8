use itertools::Itertools;
use std::fmt::Write;
use numtoa::NumToA;
use hex_literal::hex;
unsafe fn mutate(name_len: usize) {

    // let mut session_key = "A+2.1.3.0+1609480800".as_bytes_mut();
    let mut session_key = hex!("412b322e312e332e302b313630393438303830300000");
    let  (name, rem) = session_key.split_at_mut(1);
    let  (version, time) = rem.split_at_mut(9);
    println!("{:?}", name);
    println!("{:?}", version);
    println!("{:?}", time);
    for i in 1609480800..1633669093 { // 2021/01/01 to 2021/10/08 (today)

        i.numtoa(10, time);
        // println!("{}", std::mem::transmute::<&[u8], &str>(time))
        // this is degenerate
    }
}

fn main() {
    unsafe {
        mutate(1);
    }
}