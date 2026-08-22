use rustsmb::crypto::*;
fn hex(d: &[u8]) -> String { d.iter().map(|b| format!("{:02x}", b)).collect() }
fn main() {
    println!("md4(abc)   = {}", hex(&md4(b"abc")));
    println!("md4(empty) = {}", hex(&md4(b"")));
    println!("nthash(secret123) = {}", hex(&nt_hash("secret123")));
    println!("md5(abc)   = {}", hex(&md5(b"abc")));
    let h = hmac_md5(b"Jefe", b"what do ya want for nothing?");
    println!("hmac(jefe) = {}", hex(&h));
}
