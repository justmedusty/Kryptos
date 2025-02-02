#[cfg(test)]
mod cryptography_tests {
    use crate::cryptography::aes::*;
    use crate::cryptography::cryptography::Encryption;
    use crate::cryptography::rc4::Rc4State;

    macro_rules! generate_ab_arrays {
        ($size:expr) => {{
            let mut input = vec![0; $size];
            let mut output = vec![0; $size];

            for i in 0..$size {
                if i % 2 == 0 {
                    input[i] = b'B';
                    output[i] = b'B';
                } else {
                    input[i] = b'A';
                    output[i] = b'A';
                }
            }

            (input, output)
        }};
    }
    ///This test just ensures that the encryption function does in fact encrypt the plaintext input
    #[test]
    fn test_rc4_encryption() {
        let mut rc4 = Rc4State::new();
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        rc4.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    //This test just ensures that the decryption function actually decrypts , and brings back the original plaintext message
    #[test]
    fn test_rc4_decryption() {
        let mut rc4 = Rc4State::new();
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        rc4.encrypt(&input, &mut output);
        assert_ne!(input, output);
        rc4.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_cbc_encryption_128() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_128() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input); // shave off the IV
    }

    #[test]
    fn test_aes_ecb_encryption_128() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_128() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_128() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_128() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }
    #[test]
    fn test_aes_cbc_encryption_192() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_192() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ecb_encryption_192() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_192() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_192() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_192() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_cbc_encryption_256() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_256() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input); // shave off the IV
    }

    #[test]
    fn test_aes_ecb_encryption_256() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_256() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_256() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_256() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }
    /*
       Standard tests below
       https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    */
    #[test]
    fn test_ecb_encrypt_standard_test_case_128() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let plaintext: [u8;16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let plaintext = plaintext.to_vec();
        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let mut ciphertext = vec![0;16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S128, Some(&key));

        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_ecb_encrypt_standard_test_case_192() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];

        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        let plaintext = plaintext.to_vec();

        let expected_ciphertext = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
            0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        ];

        let mut ciphertext = vec![0;16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S192, Some(&key));
        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }
    #[test]
    fn test_ecb_encrypt_standard_test_case_256() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let plaintext = plaintext.to_vec();
        let expected_ciphertext = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];
        let mut ciphertext = vec![0;16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S256, Some(&key));
        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    /*
       This test just prints the keys and I manually examined them, they look good so key scheduling is correct
    */
    #[test]
    fn round_key_test() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S128, None);
        context.set_key(key.as_slice());
        context.print_round_keys(&key);

        let round_key_0 = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        assert!(context.test_round_key(&round_key_0, 0));
        let round_key_1 = [
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
            0x76, 0x05,
        ];
        assert!(context.test_round_key(&round_key_1, 1));
        let round_key_2 = [
            0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59,
            0xf6, 0x7f,
        ];
        assert!(context.test_round_key(&round_key_2, 2));
        let round_key_3 = [
            0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a,
            0x88, 0x3b,
        ];
        assert!(context.test_round_key(&round_key_3, 3));
        let round_key_4 = [
            0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b,
            0xad, 0x00,
        ];
        assert!(context.test_round_key(&round_key_4, 4));
        let round_key_5 = [
            0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9,
            0x15, 0xbc,
        ];
        assert!(context.test_round_key(&round_key_5, 5));
        let round_key_6 = [
            0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00,
            0x93, 0xfd,
        ];
        assert!(context.test_round_key(&round_key_6, 6));
        let round_key_7 = [
            0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6,
            0xdc, 0x4f,
        ];
        assert!(context.test_round_key(&round_key_7, 7));
        let round_key_8 = [
            0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d,
            0x29, 0x2f,
        ];
        assert!(context.test_round_key(&round_key_8, 8));
        let round_key_9 = [
            0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c,
            0x00, 0x6e,
        ];
        assert!(context.test_round_key(&round_key_9, 9));
        let round_key_10 = [
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
            0x0c, 0xa6,
        ];
        assert!(context.test_round_key(&round_key_10, 10));
    }
}
