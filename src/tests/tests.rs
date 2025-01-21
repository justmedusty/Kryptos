#[cfg(test)]
mod rc4tests {
    use crate::cryptography::{Rc4State, KEY_SIZE_BYTES};

    ///This test just ensures that the encryption function does in fact encrypt the plaintext input
    #[test]
    fn test_encryption() {
        let mut rc4 = Rc4State::new();
        let mut input = [0; 256];
        let mut output = [0; 256];

        for i in 0..input.len() {
            if i % 2 == 0 {
                input[i] = 'B' as u8;
                output[i] = 'B' as u8;
                continue;
            }
            output[i] = 'A' as u8;
            input[i] = 'A' as u8;
        }
        assert_eq!(input, output);
        rc4.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    //This test just ensures that the decryption function actually decrypts , and brings back the original plaintext message
    #[test]
    fn test_decryption() {
        let mut rc4 = Rc4State::new();
        let mut input = [0; KEY_SIZE_BYTES];
        let mut output = [0; KEY_SIZE_BYTES];

        for i in 0..input.len() {
            if i % 2 == 0 {
                input[i] = 'B' as u8;
                continue;
            }
            input[i] = 'A' as u8;
        }

        let original_input = input.clone();
        rc4.encrypt(&input, &mut output);
        assert_ne!(input, output);
        rc4.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }
}
