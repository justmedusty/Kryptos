pub mod salsa20 {
    use crate::cryptography::cryptography::Encryption;
    use rand::RngCore;
    use std::fmt::Debug;

    const SALSA20_KEYSIZE: usize = 32;
    const U32_MAX: u32 = 0xFFFF_FFFF; // since salsa deals with 32 bit addition mod u32 max

    const NUM_SALSA20_ROUNDS: u32 = 20;

    const SALSA20_STATE_SIZE_BYTES: usize = 64;

    const SIGMA: &str = "expand 32-byte k";

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
        fn quarter_round(state: &mut Salsa20State ,a: usize, b:  usize, c:usize, d: usize) {
            state[b] ^= Self::rotate_left( state[a] +  state[d], 7);
            state[c] ^= Self::rotate_left( state[b] +  state[a], 9);
            state[d] ^= Self::rotate_left( state[c] +  state[b], 13);
            state[a] ^= Self::rotate_left( state[d] +  state[c], 18);
        }

        fn salsa20_rounds(state: &mut Salsa20State){
            Self::quarter_round(state ,0,4,8,12);
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
