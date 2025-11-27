package com.crypto;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AESTest {

    @Test
    public void testEncryptBlockAES128() {
        // Key: 128-bit
        byte[] key = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Plaintext block
        byte[] plaintext = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2,
            (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A,
        };

        // Expected ciphertext from NIST test vector
        String expectedHex = "3AD77BB40D7A3660A89ECAF32466EF97";

        AES aes = new AES(key);
        byte[] cipher = aes.encryptBlock(plaintext);

        String actualHex = bytesToHex(cipher);

        // Assert equality
        assertEquals(expectedHex.toLowerCase(), actualHex.toLowerCase());
    }

    // Helper method for converting bytes to hex
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
