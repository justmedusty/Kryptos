use std::cmp::PartialEq;

const AES_BLOCK_LENGTH_BYTES: usize = 16;
const AES_KEY_LENGTH_BYTES_MAX: usize = 32;

const NUM_COLUMNS: u8 = 4;

type AesState = [[u8; 4]; 4];

/*
   Sbox and Rsbox as per the NIST standard
*/
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/*
Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
*  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm.
*/
const ROUND_CONSTANTS: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

fn get_sbox_number(num: u8) -> u8 {
    SBOX[num as usize]
}
fn get_sbox_inverted(num: u8) -> u8 {
    RSBOX[num as usize]
}

fn x_time(x: u8) -> u8 {
    // Left shift x by 1 position (equivalent to multiplying by 2)
    // The result will be in the 8-bit range, so we need to account for overflow.
    let shifted = x << 1;

    // If the leftmost bit of x is 1 (i.e., x >= 128), we must reduce the result
    // by XORing it with the irreducible polynomial 0x1b (which represents the reduction modulo x^8 + x^4 + x^3 + x + 1).
    let reduction = (x >> 7) & 1; // Extract the leftmost bit

    // If the leftmost bit was 1, reduce the result by XORing with 0x1b
    (shifted ^ (reduction * 0x1b))
}

fn multiply(x: u8, y: u8) -> u8 {
    // This function performs multiplication in GF(2^8) (Galois Field) using XOR and the x_time function
    return (((y & 1) * x) ^                               // If the least significant bit of y is 1, add x (no shift)
        ((y >> 1 & 1) * x_time(x)) ^                   // If the second least significant bit of y is 1, add x_time(x) (shifted by 1)
        ((y >> 2 & 1) * x_time(x_time(x))) ^           // If the third bit is 1, add x_time(x_time(x)) (shifted by 2)
        ((y >> 3 & 1) * x_time(x_time(x_time(x)))) ^   // If the fourth bit is 1, add x_time(x_time(x_time(x))) (shifted by 3)
        ((y >> 4 & 1) * x_time(x_time(x_time(x_time(x)))))); // If the fifth bit is 1, add x_time(x_time(x_time(x_time(x)))) (shifted by 4)

    // In this process, we're using the binary representation of y to determine how many times
    // to multiply x by powers of x in GF(2^8) (via x_time), and then XOR the results.
    // The multiplication follows the logic of the AES algorithm for multiplication in GF(2^8).
}

/*
    These two will get and put values as the buffer passed converted to a 2d array
    requires unsafe blocks since working with raw pointers obviously

    THIS IS ONLY SAFE IF YOU ENSURE THE RETURNED OWNED VALUE IS DROPPED
    BEFORE BUFFER IS TOUCHED
*/
fn as_2d_array(buffer: &mut [u8]) -> AesState {
    assert_eq!(buffer.len(), 16, "Buffer must have exactly 16 elements!");
    let mut arr: AesState = [[0u8; 4]; 4];
    unsafe {
        arr = *&mut *(buffer.as_mut_ptr() as *mut AesState);
    }
    arr
}

enum AesMode {
    CBC, // Cipher block chaining
    ECB, //Codebook
    CTR, // Counter
}

enum AesSize {
    S128, // 128-bit key
    S192, // 192-bit key
    S256, //256-bit key
}

struct AESContext {
    mode: AesMode,
    size: AesSize,
    //We will just allocate the max bytes rather than have differing allocations
    //it's a small allocation so who cares
    key: [u8; AES_KEY_LENGTH_BYTES_MAX],
    round_keys: [u8; 256], //240 bytes holds all of the round keys with a 256 bit key
    initialization_vector: [u8; AES_BLOCK_LENGTH_BYTES],
}

impl PartialEq<AesSize> for AesSize {
    fn eq(&self, other: &AesSize) -> bool {
        let my_size = match self {
            AesSize::S256 => 256,
            AesSize::S192 => 192,
            AesSize::S128 => 128,
        };

        let other_size = match other {
            AesSize::S256 => 256,
            AesSize::S192 => 192,
            AesSize::S128 => 128,
        };
        my_size == other_size
    }
}

impl AESContext {
    fn add_round_key(&mut self, round: u8, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] ^= self.round_keys
                    [((round * NUM_COLUMNS * 4) + (i as u8 * NUM_COLUMNS) + j as u8) as usize];
            }
        }
    }

    fn sub_bytes(&mut self, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] = get_sbox_number(state[j][i]);
            }
        }
    }

    fn inverted_sub_bytes(&mut self, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] = get_sbox_inverted(state[j][i]);
            }
        }
    }

    fn shift_rows(&mut self, state: &mut AesState) {
        let mut temp: u8;

        // Rotate first row 1 column to the left
        temp = state[0][1];
        state[0][1] = state[1][1];
        state[1][1] = state[2][1];
        state[2][1] = state[3][1];
        state[3][1] = temp;

        // Rotate second row 2 columns to the left
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;

        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;

        // Rotate third row 3 columns to the left
        temp = state[0][3];
        state[0][3] = state[3][3];
        state[3][3] = state[2][3];
        state[2][3] = state[1][3];
        state[1][3] = temp;
    }

    fn inv_shift_rows(&mut self, state: &mut AesState) {
        let mut temp: u8;
        // Rotate first row 1 column to the right
        temp = state[3][1];
        state[3][1] = state[2][1];
        state[2][1] = state[1][1];
        state[1][1] = state[0][1];
        state[0][1] = temp;

        // Rotate second row 2 columns to the right
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;

        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;

        // Rotate third row 3 columns to the right
        temp = state[0][3];
        state[0][3] = state[1][3];
        state[1][3] = state[2][3];
        state[2][3] = state[3][3];
        state[3][3] = temp;
    }
    fn inv_mix_columns(&mut self, state: &mut AesState) {
        let mut a: u8;
        let mut b: u8;
        let mut c: u8;
        let mut d: u8;

        for i in 0..4 {
            a = state[i][0];
            b = state[i][1];
            c = state[i][2];
            d = state[i][3];

            state[i][0] =
                multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
            state[i][1] =
                multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
            state[i][2] =
                multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
            state[i][3] =
                multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
        }
    }

    fn mix_columns(&mut self, state: &mut AesState) {
        let mut t: u8;
        let mut tmp: u8;
        let mut tm: u8;

        for i in 0..4 {
            t = state[i][0];
            tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];

            tm = state[i][0] ^ state[i][1];
            tm = x_time(tm);
            state[i][0] ^= tm ^ tmp;

            tm = state[i][1] ^ state[i][2];
            tm = x_time(tm);
            state[i][1] ^= tm ^ tmp;

            tm = state[i][2] ^ state[i][3];
            tm = x_time(tm);
            state[i][2] ^= tm ^ tmp;

            tm = state[i][3] ^ t;
            tm = x_time(tm);
            state[i][3] ^= tm ^ tmp;
        }
    }

    fn key_expansion(&mut self) {
        let mut temp_array: [u8; 4] = [0, 0, 0, 0]; // Used for the column/row operations
        let num_words_in_key = match self.size {
            AesSize::S128 => 4,
            AesSize::S192 => 6,
            AesSize::S256 => 8,
        }; // Number of 32-bit words in the key
        let num_columns = 4; // Number of columns (for AES)
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        }; // Number of rounds
        let mut round_key = &mut self.round_keys;

        // The first round key is the key itself.
        for i in 0..num_words_in_key {
            round_key[i * 4] = self.key[i * 4];
            round_key[i * 4 + 1] = self.key[i * 4 + 1];
            round_key[i * 4 + 2] = self.key[i * 4 + 2];
            round_key[i * 4 + 3] = self.key[i * 4 + 3];
        }

        // All other round keys are found from the previous round keys.
        for i in num_words_in_key..num_columns * (num_rounds + 1) {
            let k = (i - 1) * 4;
            temp_array[0] = round_key[k];
            temp_array[1] = round_key[k + 1];
            temp_array[2] = round_key[k + 2];
            temp_array[3] = round_key[k + 3];

            if i % num_words_in_key == 0 {
                // RotWord() function - shifts the 4 bytes in a word to the left
                let tmp = temp_array[0];
                temp_array[0] = temp_array[1];
                temp_array[1] = temp_array[2];
                temp_array[2] = temp_array[3];
                temp_array[3] = tmp;

                // SubWord() function - applies the S-box to each byte
                temp_array[0] = get_sbox_number(temp_array[0]);
                temp_array[1] = get_sbox_number(temp_array[1]);
                temp_array[2] = get_sbox_number(temp_array[2]);
                temp_array[3] = get_sbox_number(temp_array[3]);

                temp_array[0] ^= ROUND_CONSTANTS[i / num_words_in_key];
            }
            if self.size == AesSize::S256 {
                // For AES256
                if i % num_words_in_key == 4 {
                    // SubWord() function for AES256
                    temp_array[0] = get_sbox_number(temp_array[0]);
                    temp_array[1] = get_sbox_number(temp_array[1]);
                    temp_array[2] = get_sbox_number(temp_array[2]);
                    temp_array[3] = get_sbox_number(temp_array[3]);
                }
            }
            let j = i * 4;
            let k = (i - num_words_in_key) * 4;
            round_key[j] = round_key[k] ^ temp_array[0];
            round_key[j + 1] = round_key[k + 1] ^ temp_array[1];
            round_key[j + 2] = round_key[k + 2] ^ temp_array[2];
            round_key[j + 3] = round_key[k + 3] ^ temp_array[3];
        }
    }
    fn initialize_context(&mut self) {
        self.key_expansion();
    }

    fn initialize_initialization_vector(&mut self, iv: &[u8]) {
        self.key_expansion();

        for (i, byte) in iv.iter().enumerate() {
            self.initialization_vector[i] = *byte;
            if (i == AES_BLOCK_LENGTH_BYTES) {
                break;
            }
        }
    }

    /*
       Main AES cipher function, walks through each round adding the round key and
       mixing bytes. Uses the proper number of rounds based off the size of the
       AES Context object.
    */
    fn cipher(&mut self, buffer: &mut [u8]) {
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        };
        /*
           This function is only safe so long as buffer is not touched while this value
           is alive
        */
        let mut ret = as_2d_array(buffer);
        let state = &mut ret;

        self.add_round_key(0, state);

        for round in 1..=num_rounds {
            self.sub_bytes(state);
            self.shift_rows(state);
            if (round == num_rounds) {
                break;
            }
            self.mix_columns(state);
            self.add_round_key(round, state);
        }

        self.add_round_key(num_rounds, state);
    }

    fn inverted_cipher(&mut self, buffer: &mut [u8]) {
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        };

        let mut ret = as_2d_array(buffer);
        let state = &mut ret;
        self.add_round_key(num_rounds, state);

        self.add_round_key(0, state);

        for round in (num_rounds - 1)..0 {
            self.inv_shift_rows(state);
            self.inverted_sub_bytes(state);
            self.add_round_key(round, state);
            if (round == 0) {
                break;
            }
            self.inv_mix_columns(state);
        }
    }
    /*
       Xor single block in the buffer with the initialization vector stored
       internally
    */
    fn xor_with_initialization_vector(
        &mut self,
        buffer: &mut [u8],
        initialization_vector: Option<&[u8]>,
    ) {
        let use_passed = initialization_vector.is_some();
        for i in 0..AES_BLOCK_LENGTH_BYTES {
            let vector = initialization_vector.unwrap().clone();
            if (use_passed) {
                buffer[i] ^= vector[i];
            } else {
                buffer[i] ^= self.initialization_vector[i];
            }
        }
    }

    fn ecb_encrypt(&mut self, buffer: &mut [u8]) {
        self.cipher(buffer);
    }

    fn ecb_decrypt(&mut self, buffer: &mut [u8]) {
        self.inverted_cipher(buffer);
    }

    /*
       Encrypt/Decrypt in CBC mode (cipher block chaining)
       CBC xors each block with the previous block of plain/ciphertext

    */
    fn cbc_encrypt(&mut self, buffer: &mut [u8]) {
        let len = buffer.len();
        let mut current_slice = &mut buffer[0..AES_BLOCK_LENGTH_BYTES];

        let mut initialization_vector = self.initialization_vector.clone();

        for i in 0..(len / AES_BLOCK_LENGTH_BYTES) {
            self.xor_with_initialization_vector(current_slice, Some(&initialization_vector));
            self.cipher(current_slice);
            initialization_vector = <[u8; 16]>::try_from(current_slice).unwrap();
            current_slice = &mut buffer[i * AES_BLOCK_LENGTH_BYTES
                ..((i * AES_BLOCK_LENGTH_BYTES) + AES_BLOCK_LENGTH_BYTES)];
        }
        for (i, byte) in initialization_vector.iter().enumerate() {
            self.initialization_vector[i] = *byte;
        }
    }

    fn cbc_decrypt(&mut self, buffer: &mut [u8]) {
        let len = buffer.len();
        let mut current_slice = &mut buffer[0..AES_BLOCK_LENGTH_BYTES];

        let mut initialization_vector = self.initialization_vector.clone();

        for i in 0..(len / AES_BLOCK_LENGTH_BYTES) {
            for (i, byte) in current_slice.iter().enumerate() {
                initialization_vector[i] = *byte;
            }
            self.inverted_cipher(current_slice);
            self.xor_with_initialization_vector(current_slice, Some(&initialization_vector));

            for (i, byte) in current_slice.iter().enumerate() {
                initialization_vector[i] = *byte;
            }

            current_slice = &mut buffer[i * AES_BLOCK_LENGTH_BYTES
                ..((i * AES_BLOCK_LENGTH_BYTES) + AES_BLOCK_LENGTH_BYTES)];
        }
    }

    fn ctr_crypt(&mut self, buffer: &mut [u8]) {}
}
