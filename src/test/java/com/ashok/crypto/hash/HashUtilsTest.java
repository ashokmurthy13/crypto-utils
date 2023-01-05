package com.ashok.crypto.hash;

import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    @Test
    void testGenerateRandomSalt() {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);
        System.out.println(DatatypeConverter.printHexBinary(salt));
    }

    @Test
    void testCreateSHA2Hash() throws IOException, NoSuchAlgorithmException {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);
        String valueToHash = UUID.randomUUID().toString();
        byte[] hash = HashUtils.createSHA2Hash(valueToHash, salt);
        assertNotNull(hash);
        byte[] hash2 = HashUtils.createSHA2Hash(valueToHash, salt);
        assertNotNull(hash2);
        assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
    }

    @Test
    void testPasswordRoutine() {
        String secretPhrase = "correct horse battery staple";
        String hashedPassword = HashUtils.hashPassword(secretPhrase);
        boolean isSame = HashUtils.checkPassword(secretPhrase, hashedPassword);
        System.out.println(hashedPassword);
        assertTrue(isSame);
    }
}