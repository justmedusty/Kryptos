
#[cfg(test)]
mod rc4tests {
    use crate::cryptography::{Rc4State, KEY_SIZE_BYTES};
    use super::*;
    #[test]
    fn test_encryption() {
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
        assert_eq!(input, output);
        rc4.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

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
        rc4.decrypt(&output, &mut input);

        assert_eq!(input, original_input);
    }
}
