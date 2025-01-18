use rand::{rng, RngCore};
const KEY_SIZE_BYTES: usize = 256;
struct Rc4State {
    s: [u8; KEY_SIZE_BYTES],
    i: usize,
    j: usize,
    key: Option<Rc4Key>,
}

struct Rc4Key {
    key: [u8; KEY_SIZE_BYTES],
}

impl Rc4Key {
    fn new(key: [u8; KEY_SIZE_BYTES]) -> Option<Rc4Key> {
        Some(Rc4Key { key })
    }
}

impl Rc4State {
    /// Creates a new Rc4State object with a randomly generated key and default values for the s array , i , j
    fn new() -> Self {
        let mut new = Self {
            s: [0; KEY_SIZE_BYTES],
            i: 0,
            j: 0,
            key: None,
        };
        new.generate_key();
        new
    }

    /// Generates a key for your Rc4State object, this is called automatically on invocation of ::new however you can call it again if you wish to regenerate a new key
    /// The key is of size 256 bytes (4096 bits)
    fn generate_key(&mut self) {
        let mut key = [0u8; KEY_SIZE_BYTES];
        rng().fill_bytes(&mut key);
        self.key = Rc4Key::new(key);
    }

    /// key_scheduling sets up the S array (key stream) with initial values getting ready to begin the encryption process.
    /// Since RC4 is a stream cipher, you can probably imagine it is very important to generate a key stream from the key.
    /// First s is set to 1..256
    /// Then each index is swapped with the sum of that index + the Ith byte of the key + the previous value of j , mod key size, total thing also mod keysize
    fn key_scheduling(&mut self) -> Result<(), i8> {
        if self.key.is_none() {
            return Err(-1);
        }

        for i in 0..KEY_SIZE_BYTES {
            self.s[i] = i as u8;
        }

        let mut j = 0;

        let &mut key = self.key.as_mut().unwrap(); // can just call unwrap since we checked at the beginning of the function

        for i in 0..KEY_SIZE_BYTES {
            j = (j + self.s[i] as usize + key[i % KEY_SIZE_BYTES] as usize) % KEY_SIZE_BYTES;
            self.s.swap(i, j);
        }

        self.i = 0;
        self.j = 0;

        Ok(())
    }
    ///prga (pseudo-random generator algorithm) sets up the output buffer with pseudo random bytes that are derived from the initial keystream with various swaps for each byte in the buffer
    /// Finally the final output byte is grabbed from adding the value in the new swapped values of i and j in the keystream (s array) mod keysize
    fn prga(&mut self, output_buffer: &mut &[u8]) {
        for byte in output_buffer {
            self.i = (self.i + 1) % KEY_SIZE_BYTES;
            self.j = (self.j + self.s[self.i] as usize) % KEY_SIZE_BYTES;
            self.s.swap(self.i, self.j);
            let k = self.s[(self.s[self.i] as usize + self.s[self.j] as usize) % KEY_SIZE_BYTES];
            *byte = k;
        }
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {}

    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {}
}
