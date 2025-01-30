#[cfg(test)]
mod rc4tests {
    use crate::cryptography::aes::*;
    use crate::cryptography::cryptography::Encryption;
    use crate::cryptography::rc4::{Rc4State, KEY_SIZE_BYTES};

    ///This test just ensures that the encryption function does in fact encrypt the plaintext input
    #[test]
    fn test_rc4_encryption() {
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
    fn test_rc4_decryption() {
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

    #[test]
    fn test_aes_cbc_encryption() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
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
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
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

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        for byte in output.iter().by_ref() {
            print!("{:02x} ", byte);
        }
        println!(" ");
        assert_ne!(input, output);
        for byte in input.iter_mut() {
            *byte = 0;
        }
        aes.decrypt(&output, &mut input);

        for byte in output.iter().by_ref() {
            print!("{:02x} ", byte);
        }
        assert_eq!(input, original_input);
    }
}
