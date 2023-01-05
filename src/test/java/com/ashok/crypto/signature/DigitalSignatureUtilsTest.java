package com.ashok.crypto.signature;

import com.ashok.crypto.encryption.asymmetric.AsymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.*;

class DigitalSignatureUtilsTest {

    @Test
    void testDigitalSignatureRoutine() throws URISyntaxException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        URL uri = this.getClass().getClassLoader().getResource("demo.txt");
        Path path = Paths.get(uri.toURI());
        byte[] input = Files.readAllBytes(path);

        KeyPair keyPair = AsymmetricEncryptionUtils.generateKeyPair();

        byte[] signature = DigitalSignatureUtils.createDigitalSignature(input, keyPair.getPrivate());
        System.out.println(DatatypeConverter.printHexBinary(signature));
        assertTrue(DigitalSignatureUtils.verifyDigitalSignature(input, signature, keyPair.getPublic()));
    }
}