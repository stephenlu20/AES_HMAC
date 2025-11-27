package com.crypto;

public class AES {

    // AES-128 -> key length of 128 bits
    // AES-256 -> key length of 256 bits
    // 16 bytes, 4x4 matrix for state

    private int keySize;
    private int rounds;
    // holds the expansion of keys
    private byte[][][] roundKeys; 

    // Substitution box
    // Non-linear array of byte values; 0x00 to 0xff
    private static final int[] S_BOX = {

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
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

    };

    // round constants
    // refer to section 5.2 for FIPS 197; given in hexidecimal
    // Fixed 10 "words" used for key expansion
    private static int[] RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    // Constructor
    // Add AES-192 later
    public AES(byte[] key) {
        // AES-128
        if (key.length == 16) { 
            keySize = 4;
            rounds = 10;
        // AES-256
        } else if (key.length == 32) { 
            keySize = 8;
            rounds = 14;
        }

        this.roundKeys = keyExpansion(key);
    }


    // Covert byte array to state matrix
    private byte[][] convertByteArr (byte[] byteArr) {
        byte[][] state = new byte[4][4];

        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = byteArr[i];
        }
        return state;
    }

    // Covert state to byte array
    private byte[] convertState (byte[][] state) {
        byte[] byteArr = new byte[16];
        for (int i = 0; i < 16; i++) {
            byteArr[i] = state [i % 4][i / 4];
        }
        return byteArr;
    }

    // Substitution method
    // replace each byte in the state with the corresponding byte in the Substitution box
    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int sub = state[i][j] & 0xFF;
                state[i][j] = (byte) S_BOX[sub];
            }
        }
    }

    // Shift rows
    // s = sr,(c+r) mod 4 for 0 ≤ r < 4 and 0 ≤ c < 4
    // for each row i, the row is cyclically shifted to the left i times
    // refer to section 5.1.2 of FIPS197
    private void shiftRows(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            byte[] tempRow = new byte[4];
            for (int j = 0; j < 4; j++) {
                tempRow[j] = state[i][(j + i) % 4];
            }
            state[i] = tempRow;
        }
    }

    // Galois Field Multiplication; GF(2^8)
    // truthfully, the byte math java implementation is going over my head here
    // bytes cannot be multiplied like normal integres, so the Galois field is used
    // each byte in state array is interpreted as one of 256 elements of a finite field (called Galois Field or GF(2^8))
    // each byte in GF(2^8) is represented by a polynomial to define add. and mult.
    // refer to section 4: Mathematical Preliminaries of FIPS 197
    // required for doing mixColumns step of the AES cipher
    private byte galoisField(byte a, byte b) {
        int p = 0;
        int hiBitSet;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            hiBitSet = (byte) (a & 0x80);
            a <<= 1;
            if (hiBitSet != 0) a ^= 0x1b;
            b >>= 1;
        }
        return (byte)p;
    }

    // mixColumns
    // mixes the data within each column of the state array
    // multiplies each of the four columns of the state by a single fixed matrix, GF(2^8)
    // refer to section 5.1.3 of FIPS 197
    private void mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];

            state[0][c] = (byte) (galoisField(s0, (byte)0x02) ^ galoisField(s1, (byte)0x03) ^ s2 ^ s3);
            state[1][c] = (byte) (s0 ^ galoisField(s1, (byte)0x02) ^ galoisField(s2, (byte)0x03) ^ s3);
            state[2][c] = (byte) (s0 ^ s1 ^ galoisField(s2, (byte)0x02) ^ galoisField(s3, (byte)0x03));
            state[3][c] = (byte) (galoisField(s0, (byte)0x03) ^ s1 ^ s2 ^ galoisField(s3, (byte)0x02));
        }
    }

    // AddRoundKey(); section 5.1.4
    // round key is combined with the state matrix using XOR operation
    // each byte of state is XOR'd with the corresponding byte of the round key
    private void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= roundKey[i][j];
            }
        }
    }

    // keyExpansion(); section 5.2
    // takes original key and exapnds into multiple round keys
    // one key per round
    private byte[][][] keyExpansion(byte[] key) {
        // state always has 4 columns
        int columns = 4;
        // generate 4 keys per round, for n + 1 rounds
        int totalWords = columns * (rounds + 1);
        // word array is called w[i] in paper
        byte[][] w = new byte[4][totalWords];

        // loading original key
        // every 4 bytes of the key is a word
        for (int i = 0; i < keySize; i++) {
            for (int j = 0; j < 4; j++) {
                w[j][i] = key[i * 4 + j];
            }
        }

        // key expansion loop
        // from spec paper, section 5.2:
        // Every subsequent word w[i] is generated recursively from the
        // preceding word, w[i−1], and the word Nk positions earlier, w[i−Nk], as follows:
        // • If i is a multiple of Nk, then w[i] = w[i − Nk] ⊕ SUBWORD(ROTWORD(w[i − 1])) ⊕ Rcon[i/Nk].
        // • For AES-256, if i+4 is a multiple of 8, then w[i] = w[i−Nk]⊕ SUBWORD(w[i−1]).
        // • For all other cases, w[i] = w[i−Nk]⊕w[i−1]
        int rconIndex = 0;
        for (int i = keySize; i < totalWords; i++) {
            byte[] temp = { w[0][i-1], w[1][i-1], w[2][i-1], w[3][i-1] };

            if (i % keySize == 0) {
                temp = substituteWord(rotateWord(temp));
                temp[0] ^= (byte) RCON[rconIndex];
                rconIndex++;
            } else if (keySize == 8 && (i+4) % 8 == 0) {
                // AES-256 rule
                temp = substituteWord(temp);
            }
            
            for (int j = 0; j < 4; j++) {
                w[j][i] = (byte) (w[j][i - keySize] ^ temp[j]);
            }
        }

        // key formatting
        // formats the keys into a 4x4 matrix to use for each round
        byte[][][] keys = new byte[rounds+1][4][4];

        for (int round = 0; round <= rounds; round++) {
            for (int column = 0; column < 4; column++) {
                for (int row = 0; row < 4; row++) {
                    keys[round][row][column] = w[row][round * 4 + column];
                }
            }
        }

        return keys;
    }

    // Helper functions as described in 5.2

    // Rotate 4-byte word left by 1 byte
    private byte[] rotateWord(byte[] word) {
        byte[] rotated = new byte[]{word[1], word[2], word[3], word[0]};
        return rotated;
    }

    // Apply the s-box to each of the 4 bytes in a 4-byte word
    private byte[] substituteWord(byte[] word) {
        byte[] sub = new byte[4];
        for (int i = 0; i < 4; i++) {
            sub[i] = (byte) S_BOX[word[i] & 0xFF];
        }
        return sub;
    }

    // Cipher psuedocode, as described in section 5.1
    // procedure CIPHER(in, Nr, w)
    //     state ← in
    //     state ← ADDROUNDKEY(state,w[0..3])
    //         for round from 1 to Nr − 1 do
    //             state ← SUBBYTES(state)
    //             state ← SHIFTROWS(state)
    //             state ← MIXCOLUMNS(state)
    //             state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round +3])
    //         end for
    //     state ← SUBBYTES(state)
    //     state ← SHIFTROWS(state)
    //     state ← ADDROUNDKEY(state,w[4 ∗Nr..4 ∗Nr +3])
    //     return state
    // end procedure

    // Encrypt method
    public byte[] encryptBlock(byte[] input) {
        if (input.length != 16) {
            throw new IllegalArgumentException("Expecting 16 bytes. Input is " + String.valueOf(input.length) + " bytes long");
        }

        // Convert input to 4x4 AES state matrix
        byte[][] state = convertByteArr(input);

        // Initial Round Key addition
        addRoundKey(state, roundKeys[0]);

        // Rounds from 1 to Nr - 1
        for (int round = 1; round < rounds; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        // Final Round
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[rounds]);

        // Convert state matrix back to byte array
        return convertState(state);
    }
}
