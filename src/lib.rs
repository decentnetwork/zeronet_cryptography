use base64::{decode, encode};
use bitcoin::consensus::encode::{serialize, VarInt};
use bitcoin::network::constants::Network;
use bitcoin::util::base58::{check_encode_slice, from_check};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use hex::decode as hex_decode;
use ripemd160::Ripemd160;
use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};

pub mod error;
pub use error::CryptError as Error;
pub use secp256k1::SecretKey;

fn sha256d(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into_iter().collect()
}

fn hash160(input: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::default();
    hasher.update(input);
    hasher.finalize().into_iter().collect()
}

fn serialize_address(public_key: secp256k1::PublicKey) -> String {
    let serialized = public_key.serialize_uncompressed();

    let version = [0u8];
    let sha256_hash = sha256d(&serialized);
    let ripemd160_hash = hash160(sha256_hash.as_slice());

    let out = &[&version, ripemd160_hash.as_slice()].concat();

    check_encode_slice(out)
}

static MSG_SIGN_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

pub fn msg_hash(msg: &[u8]) -> Vec<u8> {
    let bytes;
    bytes = serialize(&VarInt(msg.len() as u64));
    sha256d(sha256d(&[MSG_SIGN_PREFIX, bytes.as_slice(), msg].concat()).as_slice())
}

/// Verifies that sign is a valid sign for given data and address
/// ```
/// use zeronet_cryptography::verify;
///
/// let data = "Testmessage";
/// let address = "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN";
/// let signature = "G+Hnv6dXxOAmtCj8MwQrOh5m5bV9QrmQi7DSGKiRGm9TWqWP3c5uYxUI/C/c+m9+LtYO26GbVnvuwu7hVPpUdow=";
///
/// match verify(data, address, signature) {
///    Ok(_) => println!("Signature is valid."),
///    Err(_) => println!("Signature is invalid."),
/// }
/// ```
pub fn verify<T: Into<Vec<u8>>>(data: T, valid_address: &str, sign: &str) -> Result<(), Error> {
    let sig = decode(sign)?;
    let hash = msg_hash(&data.into());

    let (sig_first, sig_r) = match sig.split_first() {
        Some(t) => t,
        None => return Err(Error::DecodeSignatureFailure),
    };

    let rec_id_v = (sig_first - 27) & 3;
    // This is not necessary for ZeroNet's cryptography
    // I've commented it out in case it is needed later.
    // // let rec_compact = (sig_first - 27) & 4 != 0;
    let rec_id = secp256k1::recovery::RecoveryId::from_i32(rec_id_v as i32)?;
    let signature = secp256k1::recovery::RecoverableSignature::from_compact(sig_r, rec_id)?;
    let message = secp256k1::Message::from_slice(hash.as_slice())?;
    let secp = Secp256k1::new();
    let recovered: secp256k1::PublicKey = secp.recover(&message, &signature)?;
    let address = serialize_address(recovered);

    if address == valid_address {
        return Ok(());
    }
    Err(Error::AddressMismatch(address))
}

/// Generate a valid signature for given data and private key
/// ```
/// use zeronet_cryptography::sign;
///
/// let data = "Testmessage";
/// let private_key = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
///
/// match sign(data, private_key) {
///    Ok(signature) => println!("The signature is {}", signature),
///    Err(_) => println!("An error occured during the signing process"),
/// }
/// ```
pub fn sign<T: Into<Vec<u8>>>(data: T, privkey: &str) -> Result<String, Error> {
    let privkey_bytes = wif_to_privkey(privkey)?;

    let privkey = secp256k1::SecretKey::from_slice(&privkey_bytes)?;
    let hash = msg_hash(&data.into());
    let message = secp256k1::Message::from_slice(hash.as_slice())?;
    let secp = Secp256k1::new();
    let sig = secp.sign_recoverable(&message, &privkey);
    let (rec_id, ser_c) = sig.serialize_compact();
    let ser_c_v: [&[u8]; 2] = [&[(rec_id.to_i32() + 27) as u8], &ser_c];

    let s = encode(&ser_c_v.concat());
    Ok(s)
}

/// Create a public key from a private key
/// ```
/// use zeronet_cryptography::privkey_to_pubkey;
/// const PRIVKEY: &str = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
/// const PUBKEY: &str = "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN";
///
/// let pubkey = privkey_to_pubkey(PRIVKEY).unwrap();
///
/// assert_eq!(pubkey, PUBKEY);
/// ```
pub fn privkey_to_pubkey(privkey: &str) -> Result<String, Error> {
    let privkey_bytes = wif_to_privkey(privkey)?;

    let secp = Secp256k1::new();
    let privkey = secp256k1::SecretKey::from_slice(&privkey_bytes)?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);
    let pubkey = serialize_address(pubkey);
    Ok(pubkey)
}

/// Converts a seed (hex-encoded) into a private key
/// ```
/// use zeronet_cryptography::{seed_to_privkey, SecretKey};
/// const SEED: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// const PRIVKEY_BYTES: &[u8] = &[
///     227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
///    228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
/// ];
/// let expected_privkey = SecretKey::from_slice(PRIVKEY_BYTES).unwrap();
/// let privkey = seed_to_privkey(SEED).unwrap();
///
/// assert_eq!(privkey, expected_privkey);
/// ```
pub fn seed_to_privkey(seed: &str) -> Result<SecretKey, Error> {
    // TODO: needs error handling
    let privkey_bytes = hex_decode(seed).unwrap();

    // TODO: needs some checking like: privkey length and etc
    let privkey = SecretKey::from_slice(&privkey_bytes)?;
    Ok(privkey)
}

/// Converts a private key into a Wallet Import Format (WIF) string
/// ```
/// use zeronet_cryptography::{SecretKey, privkey_to_wif};
///
/// const PRIVKEY: &str = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
/// const PRIVKEY_BYTES: &[u8] = &[
/// 227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
/// 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
/// ];
///
/// let priv_key = SecretKey::from_slice(PRIVKEY_BYTES).unwrap();
/// let wif_privkey = privkey_to_wif(priv_key);
/// assert_eq!(PRIVKEY, wif_privkey);
/// ```
pub fn privkey_to_wif(priv_key: SecretKey) -> String {
    let slice: &[u8] = &priv_key[..];
    let mut bytes = vec![128];
    bytes.extend_from_slice(slice);

    #[allow(clippy::let_and_return)]
    let priv_key = check_encode_slice(&bytes);
    priv_key
}

/// Converts a WIF-encoded private key into a byte array
/// ```
/// use zeronet_cryptography::{SecretKey, wif_to_privkey};
///
/// const PRIVKEY: &str = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
/// const PRIVKEY_BYTES: &[u8] = &[
/// 227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
/// 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
/// ];
///
/// let priv_key = wif_to_privkey(PRIVKEY).unwrap();
/// assert_eq!(PRIVKEY_BYTES, priv_key);
/// ```
pub fn wif_to_privkey(wif_privkey: &str) -> Result<Vec<u8>, Error> {
    let priv_key = from_check(wif_privkey);

    match priv_key {
        Ok(key) => match key[0] {
      128 /* 0x80 */ => Ok(key[1..].to_vec()),
      _ => Err(Error::InvalidNetworkKey),
    },
        Err(_) => Err(Error::InvalidWIFPrivKey),
    }
}

/// Create a valid key pair
/// ```
/// use zeronet_cryptography::create;
///
/// let (priv_key, pub_key) = create();
/// ```
pub fn create() -> (SecretKey, String) {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();
    let (priv_key, address) = secp.generate_keypair(&mut rng);

    let address = serialize_address(address);

    (priv_key, address)
}

/// Derives a child private key from a given seed and child index using hierarchical deterministic (HD) key derivation
/// ```
/// use zeronet_cryptography::{SecretKey, hd_privkey};
///
/// const SEED: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// const CHILD_INDEX: u32 = 45168996;
/// const CHILD_PRIVKEY: &[u8] = &[
/// 29, 131, 147, 25, 178, 182, 122, 121, 93, 19, 157, 0, 138, 212, 126,
/// 103, 77, 161, 219, 149, 20, 171, 72, 118, 67, 23, 189, 83, 8, 0, 172, 63
/// ];
///
/// let expected_key = SecretKey::from_slice(CHILD_PRIVKEY).unwrap();
///
/// let child_privkey = hd_privkey(SEED, CHILD_INDEX);
///
/// assert_eq!(expected_key, child_privkey);
/// ```
pub fn hd_privkey(seed: &str, child_idx: u32) -> SecretKey {
    let seed_bytes = hex_decode(&seed).unwrap();

    let xprivkey = ExtendedPrivKey::new_master(Network::Bitcoin, &seed_bytes).unwrap();

    let secp = Secp256k1::new();
    let child_num = ChildNumber::from_normal_idx(child_idx).unwrap();
    let child_privkey = xprivkey.ckd_priv(&secp, child_num).unwrap();

    child_privkey.private_key.key
}

#[cfg(test)]
#[cfg_attr(tarpaulin, ignore)]
mod tests {
    use super::*;

    const PUBKEY: &str = "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN";
    const PRIVKEY: &str = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
    const SEED: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const CHILD_PRIVKEY: &str = "5J3HUZpcNuEMmFMec9haxPJ58GiEHruqYDLtMGtFAumaLMr5dCV";
    const PRIVKEY_BYTES: &[u8] = &[
        227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
        228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
    ];
    const CHILD_INDEX: u32 = 45168996;
    const MESSAGE: &str = "Testmessage";
    const SIGNATURE: &str =
        "G+Hnv6dXxOAmtCj8MwQrOh5m5bV9QrmQi7DSGKiRGm9TWqWP3c5uYxUI/C/c+m9+LtYO26GbVnvuwu7hVPpUdow=";
    const MSG_HASH: &[u8] = &[
        250, 76, 36, 63, 188, 246, 57, 82, 210, 190, 131, 30, 80, 21, 194, 116, 202, 29, 102, 133,
        20, 205, 34, 11, 215, 177, 255, 148, 166, 130, 107, 161,
    ];

    #[test]
    fn test_privkey_to_pubkey() {
        let pub_key = privkey_to_pubkey(PRIVKEY).unwrap();
        assert_eq!(pub_key, PUBKEY);
    }

    #[test]
    fn test_msg_hash() {
        let result = msg_hash(MESSAGE.as_bytes());
        assert_eq!(result, MSG_HASH);
    }

    #[test]
    fn test_verification() {
        let result = verify(MESSAGE, PUBKEY, SIGNATURE);
        assert_eq!(result.is_ok(), true);

        let result = verify(MESSAGE.as_bytes(), PUBKEY, "i");
        assert_eq!(result.unwrap_err(), Error::DecodeSignatureFailure);
    }

    #[test]
    fn test_signing() {
        let result = sign(MESSAGE, PRIVKEY);
        assert_eq!(result.is_ok(), true);
        let result2 = verify(MESSAGE, PUBKEY, &result.unwrap());
        assert_eq!(result2.is_ok(), true);
    }

    #[test]
    fn test_creating() {
        let (priv_key, address) = create();
        let priv_key = privkey_to_wif(priv_key);

        let signature = sign(MESSAGE, &priv_key).unwrap();
        let result = verify(MESSAGE, &address, &signature);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_derive_child_privkey() {
        let child_privkey = hd_privkey(SEED, CHILD_INDEX);

        assert_eq!(privkey_to_wif(child_privkey), CHILD_PRIVKEY);
    }

    #[test]
    fn test_wif_to_privkey() {
        let priv_key = wif_to_privkey(PRIVKEY).unwrap();
        assert_eq!(PRIVKEY_BYTES, priv_key);
    }

    #[test]
    fn test_privkey_to_wif() {
        let priv_key = SecretKey::from_slice(PRIVKEY_BYTES).unwrap();

        let wif_privkey = privkey_to_wif(priv_key);
        assert_eq!(PRIVKEY, wif_privkey);
    }

    #[test]
    fn test_seed_to_privkey() {
        let expected_privkey = SecretKey::from_slice(PRIVKEY_BYTES).unwrap();
        let privkey = seed_to_privkey(SEED).unwrap();

        assert_eq!(privkey, expected_privkey);
    }
}
