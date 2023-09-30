use std::{collections::HashMap, fs::read_to_string, path::Path};

use hex::decode;
use serde::Deserialize;

use cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa20;

use super::IV_BYTES;

const BLOCK_SIZE: usize = 64;

#[test]
fn ecrypt_test_vectors_256_bit_key() {
    let key_bytes = KeyBits::Bits256;

    let json = match key_bytes {
        KeyBits::Bits128 => {
            EcryptTestVector::json("./tests/ecrypt/test_vectors_128.json".to_string())
        }
        KeyBits::Bits256 => {
            EcryptTestVector::json("./tests/ecrypt/test_vectors_256.json".to_string())
        }
    };

    for map in json {
        if let Some(test_data) = map.values().last() {
            let key = test_data.key();

            let iv = test_data.iv();

            let (stream1_index, stream1_expected) = test_data.stream1();
            let (stream2_index, stream2_expected) = test_data.stream2();
            let (stream3_index, stream3_expected) = test_data.stream3();
            let (stream4_index, stream4_expected) = test_data.stream4();

            let mut cipher = match key_bytes {
                KeyBits::Bits128 => {
                    let _key_as_array: [u8; 16] = key.try_into().expect("data do not fit");
                    panic!("128 bit key size is not supported")
                }
                KeyBits::Bits256 => {
                    let key_as_array: [u8; 32] = key.try_into().expect("data do not fit");
                    Salsa20::new(&key_as_array.into(), &iv.into())
                }
            };

            let mut buf = vec![0; stream4_index + BLOCK_SIZE];
            cipher.apply_keystream(&mut buf);

            // Test stream 1
            for i in stream1_index..(stream1_index + BLOCK_SIZE) {
                assert_eq!(buf[i], stream1_expected[i])
            }

            // Test stream 2
            for (c, i) in (stream2_index..(stream2_index + BLOCK_SIZE)).enumerate() {
                assert_eq!(buf[i], stream2_expected[c]);
            }

            // Test stream 3
            for (c, i) in (stream3_index..(stream3_index + BLOCK_SIZE)).enumerate() {
                assert_eq!(buf[i], stream3_expected[c]);
            }

            // Test stream 4
            for (c, i) in (stream4_index..(stream4_index + BLOCK_SIZE)).enumerate() {
                assert_eq!(buf[i], stream4_expected[c]);
            }

            // TODO: xor-digest
            // https://www.cosic.esat.kuleuven.be/nessie/testvectors/sc-title.html
        }
    }
}

#[derive(Deserialize)]
struct EcryptTestVector {
    key1: String,
    key2: Option<String>,
    iv: String,
    #[serde(alias = "stream1index")]
    stream1_index: usize,
    #[serde(alias = "stream1expected")]
    stream1_expected: String,
    #[serde(alias = "stream2index")]
    stream2_index: usize,
    #[serde(alias = "stream2expected")]
    stream2_expected: String,
    #[serde(alias = "stream3index")]
    stream3_index: usize,
    #[serde(alias = "stream3expected")]
    stream3_expected: String,
    #[serde(alias = "stream4index")]
    stream4_index: usize,
    #[serde(alias = "stream4expected")]
    stream4_expected: String,
    #[allow(dead_code)]
    #[serde(alias = "xordigest")]
    xor_digest: String,
}

enum KeyBits {
    #[allow(dead_code)]
    Bits128,
    Bits256,
}

impl EcryptTestVector {
    fn json(path_string: String) -> Vec<HashMap<String, EcryptTestVector>> {
        let path = Path::new(&path_string);
        let data = read_to_string(path).expect("path to json file  not found");

        serde_json::from_str(data.as_str()).expect("provided json is not valid ecrypt format")
    }

    fn key(&self) -> Vec<u8> {
        let merged_key = match &self.key2 {
            Some(key2) => format!("{}{}", self.key1, key2),
            None => self.key1.clone(),
        };
        let key = decode(&merged_key).expect("invalid hex string");

        key.try_into().expect("data do not fit")
    }

    fn iv(&self) -> [u8; IV_BYTES] {
        let iv = decode(&self.iv).expect("invalid hex string");

        iv.try_into().expect("data do not fit")
    }

    fn stream1(&self) -> (usize, Vec<u8>) {
        (
            self.stream1_index,
            decode(&self.stream1_expected).expect("invalid hex string"),
        )
    }

    fn stream2(&self) -> (usize, Vec<u8>) {
        (
            self.stream2_index,
            decode(&self.stream2_expected).expect("invalid hex string"),
        )
    }

    fn stream3(&self) -> (usize, Vec<u8>) {
        (
            self.stream3_index,
            decode(&self.stream3_expected).expect("invalid hex string"),
        )
    }

    fn stream4(&self) -> (usize, Vec<u8>) {
        (
            self.stream4_index,
            decode(&self.stream4_expected).expect("invalid hex string"),
        )
    }
}
