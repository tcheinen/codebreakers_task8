use ring::digest::{Context, Digest, SHA256};
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};
use std::io::{stdin, BufRead};

fn sha256_digest(data: &[u8]) -> Digest {
    let mut context = Context::new(&SHA256);
    context.update(data);
    context.finish()
}

fn main() {
    let digest = sha256_digest(std::env::args().nth(1).expect("1st arg to be set").as_ref());
    let key = Key::from_slice(digest.as_ref()).expect("lmao invalid key");

    stdin()
        .lock()
        .lines()
        .map(|x| x.expect("line to be read"))
        .map(|x| x.trim_end().to_string())
        .map(|x| hex::decode(x).unwrap())
        .map(|x| {

            let nonce = Nonce::from_slice(&x[4..28]).expect("lmao invalid nonce");
            let cipher = &x[28..];
            if let Ok(inner) =
                sodiumoxide::crypto::secretbox::xsalsa20poly1305::open(cipher, &nonce, &key)
            {
                inner
            } else {
                vec![]
                // panic!("couldn't decrypt????");
            }
        })
        .map(|x| hex::encode(x))
        .for_each(|x| println!("{}", x))
}
//
