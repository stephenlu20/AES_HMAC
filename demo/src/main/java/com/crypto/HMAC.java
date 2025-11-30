package com.crypto;

public class HMAC {

    private static final int BLOCK_SIZE = 64;

    private final SHA256 sha256;
    private byte[] key;

    public HMAC(byte[] key) {
        this.sha256 = new SHA256();
        setKey(key);
    }

    private void setKey(byte[] key) {
        if (key.length > BLOCK_SIZE) {
            throw new IllegalArgumentException("Key too long");
        }

        // in case the key is smaller than 64 bytes
        // create a key that is 64 bytes long and transfer
        // the old key over
        // the rest is "padding"
        byte[] newKey = new byte[BLOCK_SIZE];

        for (int i = 0; i < key.length; i++) {
            newKey[i] = key[i];
        }

        this.key = newKey;
    }

    public byte[] compute(byte[] message) {
        // initialize separate inner and outer keys for hashing
        byte[] innerKey = new byte[BLOCK_SIZE];
        byte[] outerKey = new byte[BLOCK_SIZE];

        // both keys are XOR'd with different hex values to look like different keys
        for (int i = 0; i < BLOCK_SIZE; i++) {
            innerKey[i] = (byte) (key[i] ^ 0x36);
            outerKey[i] = (byte) (key[i] ^ 0x5C);
        }

        // make sure we hash with the initial hash values
        sha256.reset();
        // concatenate inner key with the message and then hash
        byte[] keyWithMessage = concat(innerKey, message);
        byte[] innerHash = sha256.hash(keyWithMessage);

        // make sure we hash with the initial hash values
        sha256.reset();
        // concatenate outer key with the hash made from the inner key and message, and then hash
        byte[] outerHash = concat(outerKey, innerHash);
        return sha256.hash(outerHash);
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];

        for (int i = 0; i < a.length; i++) {
            result[i] = a[i];
        }
        for (int i = 0; i < b.length; i++) {
            result[a.length + i] = b[i];
        }
        return result;
    }
}
