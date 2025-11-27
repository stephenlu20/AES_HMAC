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

    @Test
    public void testEncryptBlocksAES128() {
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
            
            (byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57,
            (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C,
            (byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC,
            (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51,
            
            (byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46,
            (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11,
            (byte)0xE5, (byte)0xFB, (byte)0xC1, (byte)0x19,
            (byte)0x1A, (byte)0x0A, (byte)0x52, (byte)0xEF,
            
            (byte)0xF6, (byte)0x9F, (byte)0x24, (byte)0x45,
            (byte)0xDF, (byte)0x4F, (byte)0x9B, (byte)0x17,
            (byte)0xAD, (byte)0x2B, (byte)0x41, (byte)0x7B,
            (byte)0xE6, (byte)0x6C, (byte)0x37, (byte)0x10
        };

        // Expected ciphertext from NIST test vector
        String expectedHex = "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4";

        AES aes = new AES(key);
        byte[] cipher = aes.encryptBlocks(plaintext);

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
