pub mod salsa20 {

    const SALSA20_KEYSIZE: usize = 32;
    const U32_MAX: u32 = 0xFFFF_FFFF; // since cha cha deals with 32 bit addition mod u32 max

    const NUM_SALSA20_ROUNDS: u32 = 20;

    const SALSA20_STATE_SIZE_BYTES: usize = 64;

    type Salsa20Nonce = u64;
    type Salsa20Counter = u64;

    type Salsa20State = [u32; 16]; // salsa20 state is a 4x4 matrix of 32 bit words
    pub struct Salsa2020Context {
        key: [u8; SALSA20_KEYSIZE], // we will only support full size keys
        nonce: Salsa20Nonce,
        counter: Salsa20Counter,
    }
}
