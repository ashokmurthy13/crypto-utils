package com.ashok.crypto.encryption.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SymmetricEncryptionUtilsTest {

    @Test
    void testCreateAESKey() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtils.generateAESKey();
        assertNotNull(secretKey);
        System.out.println(DatatypeConverter.printHexBinary(secretKey.getEncoded()));
    }

    @Test
    void testAESCryptoRoutine() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtils.generateAESKey();
        byte[] iv = SymmetricEncryptionUtils.createInitializationVector();
        String plainText = "Welcome to Cryptography. Lets encrypt and decrypt using AES Symmetric Encryption";

        byte[] encrypted = SymmetricEncryptionUtils.performAESEncryption(plainText, secretKey, iv);
        assertNotNull(encrypted);
        System.out.println(DatatypeConverter.printHexBinary(encrypted));

        String decrypted = SymmetricEncryptionUtils.performAESDecryption(encrypted, secretKey, iv);
        assertNotNull(decrypted);
        assertEquals(plainText, decrypted);
    }
}