pub mod salsa20 {
    use crate::cryptography::cryptography::Encryption;
    use rand::RngCore;
    use std::fmt::Debug;

    const SALSA20_KEYSIZE: usize = 32;
    const U32_MAX: u32 = 0xFFFF_FFFF; // since salsa deals with 32 bit addition mod u32 max

    const NUM_SALSA20_ROUNDS: u32 = 20;

    const SALSA20_STATE_SIZE_BYTES: usize = 64;

    const SIGMA: &[u8; 16] = b"expand 32-byte k";

    type Salsa20Nonce = [u8; 8];
    type Salsa20Counter = [u8; 8];

    type Salsa20Key = [u8; SALSA20_KEYSIZE];

    type Salsa20State = [u32; 16]; // salsa20 state is a 4x4 matrix of 32 bit words
    pub struct Salsa2020Context {
        key: Salsa20Key, // we will only support full size keys
        nonce: Salsa20Nonce,
        counter: Salsa20Counter,
    }

    impl Salsa2020Context {
        pub fn new() -> Salsa2020Context {
            todo!()
        }
        #[inline]
        pub fn generate_nonce(&mut self) {
            rand::rng().fill_bytes(&mut self.nonce);
        }
        #[inline]
        pub fn generate_key(&mut self) {
            rand::rng().fill_bytes(&mut self.key);
        }
        #[inline]
        fn rotate_left(a: u32, b: u32) -> u32 {
            (a << b) | (a >> (32 - b))
        }

        /*
           Core Salsa20 Algorithm operates on each column of the 4x4 matrix
        */
        #[inline]
        fn salsa20_quarter_round(state: &mut Salsa20State, a: usize, b: usize, c: usize, d: usize) {
            state[b] ^= Self::rotate_left(state[a] + state[d], 7);
            state[c] ^= Self::rotate_left(state[b] + state[a], 9);
            state[d] ^= Self::rotate_left(state[c] + state[b], 13);
            state[a] ^= Self::rotate_left(state[d] + state[c], 18);
        }

        fn salsa20_double_rounds(state: &mut Salsa20State) {
            //column round
            Self::salsa20_quarter_round(state, 0, 4, 8, 12);
            Self::salsa20_quarter_round(state, 5, 9, 13, 1);
            Self::salsa20_quarter_round(state, 10, 14, 2, 6);
            Self::salsa20_quarter_round(state, 15, 3, 7, 11);
            //row round
            Self::salsa20_quarter_round(state, 0, 1, 2, 3);
            Self::salsa20_quarter_round(state, 5, 6, 7, 4);
            Self::salsa20_quarter_round(state, 10, 14, 2, 6);
            Self::salsa20_quarter_round(state, 15, 12, 13, 14);
        }

        fn salsa20_little_endian_word(byte: &[u8; 4]) -> u32 {
            ((byte[0] as u32)
                + (byte[1] << 8u32) as u32
                + (byte[2] << 16u32) as u32
                + (byte[3] << 24u32) as u32)
        }

        fn salsa20_reverse_little_endian_word(byte: &mut [u8; 4], word: u32) {
            byte[0] = word as u8;
            byte[1] = (word >> 8) as u8;
            byte[2] = (word >> 16) as u8;
            byte[3] = (word >> 24) as u8;
        }

        fn salsa20_hash(sequence: &mut [u8; 64]) {
            let mut x: Salsa20State = [0u32; 16];
            let mut z: Salsa20State = [0u32; 16];

            for i in 0..16 {
                let result = Self::salsa20_little_endian_word(
                    <&[u8; 4]>::try_from(&sequence[i * 4..(i * 4) + 4]).unwrap(),
                ); // this may be dicey we will see
                x[i] = result;
                z[i] = result;
            }

            for _ in 0..10 {
                Self::salsa20_double_rounds(&mut z);
            }

            for i in 0..16 {
                z[i] += x[i];
                Self::salsa20_reverse_little_endian_word(
                    <&mut [u8; 4]>::try_from(&mut sequence[i * 4..(i * 4) + 4]).unwrap(),
                    z[i],
                );
            }
        }
    }

    impl Encryption for Salsa2020Context {
        fn initialize_context(&mut self) {
            todo!()
        }

        fn encrypt(&mut self, input: &mut Vec<u8>, output: &mut Vec<u8>) {
            todo!()
        }

        fn decrypt(&mut self, input: &mut Vec<u8>, output: &mut Vec<u8>) {
            todo!()
        }

        fn set_key(&mut self, key: &[u8]) {
            for (i, byte) in key.iter().enumerate() {
                if (i > SALSA20_KEYSIZE) {
                    return;
                }
                self.key[i] = *byte;
            }
        }

        fn get_key(&self) -> &[u8] {
            &self.key
        }
    }
}
