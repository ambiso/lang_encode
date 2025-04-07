use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::rc::Rc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};

#[derive(Debug)]
enum HuffmanNode {
    Leaf {
        byte: u8,
    },
    Internal {
        left: Rc<HuffmanNode>,
        right: Rc<HuffmanNode>,
    },
}

#[derive(Debug)]
struct HuffmanTree {
    root: Rc<HuffmanNode>,
    codes: HashMap<u8, Vec<bool>>,
}

#[derive(Debug)]
struct HeapNode {
    freq: usize,
    node: Rc<HuffmanNode>,
}

impl PartialEq for HeapNode {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
    }
}
impl Eq for HeapNode {}
impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.freq.cmp(&self.freq)
    }
}

impl HuffmanTree {
    pub fn build(freqs: &HashMap<u8, usize>) -> Self {
        let mut heap = BinaryHeap::new();

        for (&byte, &freq) in freqs {
            let node = Rc::new(HuffmanNode::Leaf { byte });
            heap.push(HeapNode { freq, node });
        }

        while heap.len() > 1 {
            let left = heap.pop().unwrap();
            let right = heap.pop().unwrap();

            let node = Rc::new(HuffmanNode::Internal {
                left: left.node,
                right: right.node,
            });

            heap.push(HeapNode {
                freq: left.freq + right.freq,
                node,
            });
        }

        let root = heap.pop().unwrap().node;
        let mut codes = HashMap::new();
        Self::build_codes(&root, vec![], &mut codes);

        HuffmanTree { root, codes }
    }

    fn build_codes(node: &Rc<HuffmanNode>, prefix: Vec<bool>, codes: &mut HashMap<u8, Vec<bool>>) {
        match &**node {
            HuffmanNode::Leaf { byte } => {
                codes.insert(*byte, prefix);
            }
            HuffmanNode::Internal { left, right } => {
                let mut left_prefix = prefix.clone();
                left_prefix.push(false);
                Self::build_codes(left, left_prefix, codes);

                let mut right_prefix = prefix.clone();
                right_prefix.push(true);
                Self::build_codes(right, right_prefix, codes);
            }
        }
    }

    pub fn encode(&self, data: &[u8]) -> Vec<bool> {
        let mut encoded = Vec::new();
        for &byte in data {
            if let Some(code) = self.codes.get(&byte) {
                encoded.extend_from_slice(code);
            }
        }
        encoded
    }

    pub fn decode(&self, bits: &[bool]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut current = &self.root;

        let mut i = 0;
        loop {
            let bit = if i < bits.len() { bits[i] } else { false };
            current = match &**current {
                HuffmanNode::Internal { left, right } => {
                    if !bit {
                        left
                    } else {
                        right
                    }
                }
                HuffmanNode::Leaf { .. } => &self.root,
            };

            if let HuffmanNode::Leaf { byte } = &**current {
                result.push(*byte);
                if i >= bits.len() {
                    // pad with 0s until we push out a symbol
                    break;
                }
                current = &self.root;
            }
            i += 1;
        }

        result
    }
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for &byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    assert!(bits.len() % 8 == 0, "Number of bits must be divisible by 8");
    let mut bytes = Vec::new();

    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }

    bytes
}

fn main() {
    let freqs = HashMap::from([
        (b'e', 1270),
        (b't', 910),
        (b'a', 820),
        (b'o', 750),
        (b'i', 700),
        (b'n', 670),
        (b's', 630),
        (b'h', 610),
        (b'r', 600),
        (b'd', 430),
        (b'l', 400),
        (b'c', 280),
        (b'u', 280),
        (b'm', 240),
        (b'w', 240),
        (b'f', 220),
        (b'g', 200),
        (b'y', 200),
        (b'p', 190),
        (b'b', 150),
        (b'v', 98),
        (b'k', 77),
        (b'j', 15),
        (b'x', 15),
        (b'q', 9),
        (b'z', 7),
    ]);
    let tree = HuffmanTree::build(&freqs);

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from(rand::random::<[u8; 12]>());

    let plaintext = b"hello world";
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("encryption failed");

    let encrypted_bits = bytes_to_bits(&ciphertext);

    let decoded = tree.decode(&encrypted_bits);

    println!("Plaintext: {:?}", plaintext);
    println!("Ciphertext (bytes): {:?}", ciphertext);
    println!("Ciphertext (bits): {:?}", encrypted_bits);
    println!("Huffman-decoded: {:?}", std::str::from_utf8(&decoded));

    let mut bits = tree.encode(&decoded);
    // remove padding bits
    bits.truncate(bits.len() / 8 * 8);

    let ciphertext2 = bits_to_bytes(&bits);
    assert_eq!(ciphertext, ciphertext);

    let plaintext2 = cipher.decrypt(&nonce, ciphertext2.as_ref()).unwrap();

    assert_eq!(plaintext.as_slice(), &plaintext2);

    println!("Plaintext2: {:?}", std::str::from_utf8(&plaintext2));
}
