use rand::{rngs::ThreadRng, RngCore};

const KEY_SIZE_BYTES: usize = 256;

struct Rc4State {
    s: [u8; KEY_SIZE_BYTES],
    i: usize,
    j: usize,
    key: Rc4Key,
}

struct Rc4Key {
    key: [u8; KEY_SIZE_BYTES],
}

impl Rc4Key {
    fn new(key: [u8; KEY_SIZE_BYTES]) -> Rc4Key {
        Rc4Key { key }
    }
}

impl Rc4State {
    /// Creates a new Rc4State object with a randomly generated key and default values for the s array, i, j
    fn new() -> Self {
        let mut new = Self {
            s: [0; KEY_SIZE_BYTES],
            i: 0,
            j: 0,
            key: Rc4Key::new([0; KEY_SIZE_BYTES]), // Initialize with a default key
        };

        new.initialize();
        new
    }

    fn initialize(&mut self) {
        self.generate_key();
        self.key_scheduling();
    }

    /// Generates a key for your Rc4State object, this is called automatically on invocation of ::new however you can call it again if you wish to regenerate a new key
    /// The key is of size 256 bytes (4096 bits)
    fn generate_key(&mut self) {
        let mut key = [0u8; KEY_SIZE_BYTES];
        rand::thread_rng().fill_bytes(&mut key); // Fixed to use a random generator
        self.key = Rc4Key::new(key);
    }

    /// key_scheduling sets up the S array (key stream) with initial values getting ready to begin the encryption process.
    fn key_scheduling(&mut self) {
        let key = &self.key.key;

        // Initialize the s array to the range [0..255]
        for i in 0..KEY_SIZE_BYTES {
            self.s[i] = i as u8;
        }

        let mut j = 0;

        for i in 0..KEY_SIZE_BYTES {
            j = (j + self.s[i] as usize + key[i] as usize) % KEY_SIZE_BYTES;
            self.s.swap(i, j);
        }

    }

    /// prga (pseudo-random generator algorithm) sets up the keystream buffer with pseudo random bytes derived from the initial keystream
    fn prga(&mut self, output_buffer: &mut [u8]) {
        self.i = 0;
        self.j = 0;
        for byte in output_buffer {
            self.i = (self.i + 1) % KEY_SIZE_BYTES;
            self.j = (self.j + self.s[self.i] as usize) % KEY_SIZE_BYTES;
            self.s.swap(self.i, self.j);
            let k = self.s[(self.s[self.i] as usize + self.s[self.j] as usize) % KEY_SIZE_BYTES];
            *byte = k;
        }
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        let mut keystream = vec![0u8; input.len()];
        self.prga(&mut keystream);

        for (i, &input_byte) in input.iter().enumerate() {
            output[i] = keystream[i] ^ input_byte;
        }
    }

    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.encrypt(input, output);
    }
}

#[cfg(test)]
mod rc4tests {
    use super::*;
    #[test]
    fn test_encryption() {
        let mut rc4 = Rc4State::new();
        let mut input = [0; 256];
        let mut output = [0; 256];
        /// Set them both just so we can ensure they are not the same after
        ///
        for i in 0..input.len() {
            if (i % 2 == 0) {
                input[i] = 'B' as u8;
                output[i] = 'B' as u8;
                continue;
            }
            output[i] = 'A' as u8;
            input[i] = 'A' as u8;
        }
        assert_eq!(input,output);
        rc4.encrypt(&input, &mut output);

        for i in 0..output.len() {
            print!("output {} : input {}\n", output[i], input[i]);
        }

        assert_ne!(input, output);
    }

    #[test]
    fn test_decryption() {
        let mut rc4 = Rc4State::new();
        let mut input = [0; 256];
        let mut output = [0; 256];
        /// Set them both just so we can ensure they are not the same after
        for i in 0..input.len() {
            if (i % 2 == 0) {
                input[i] = 'B' as u8;
                output[i] = 'B' as u8;
                continue;
            }
            output[i] = 'A' as u8;
            input[i] = 'A' as u8;
        }

        rc4.encrypt(&input, &mut output);


        rc4.decrypt(&output, &mut input);

        for i in 0..output.len() {
            print!("output {} : input {}\n", output[i], input[i]);
        }

        assert_eq!(input, output);
    }
}
