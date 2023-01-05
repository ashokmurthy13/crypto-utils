package com.ashok.crypto.encryption.asymmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AsymmetricEncryptionUtilsTest {

    @Test
    void testGenerateKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private Key : " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key  : " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
    }

    @Test
    void testRSACryptoRoutine() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateKeyPair();
        String plainText = "Welcome to Cryptography. Lets encrypt and decrypt using RSA Asymmetric Encryption";

        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));

        String decrypted = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decrypted);
    }
}