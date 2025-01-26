const AES_BLOCK_LENGTH_BYTES: usize = 16;
const AES_KEY_LENGTH_BYTES_MAX: usize = 32;

enum Mode {
    CBC, // Cipher block chaining
    ECB, //Codebook
    CTR, // Counter
}

enum Size {
    S128, // 128-bit key
    S192, // 192-bit key
    S256, //256-bit key
}

struct AESContext {
    mode: Mode,
    size: Size,
    //We will just allocate the max bytes rather than have differing allocations
    //it's a small allocation so who cares
    round_key: [u8; AES_KEY_LENGTH_BYTES_MAX],
    initialization_vector: [u8; AES_BLOCK_LENGTH_BYTES],
}
