package org.apache.spark.palantir.shuffle.async.util;

import com.google.common.base.Throwables;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyPairs {
    private KeyPairs() {
    }

    public static KeyPair fromPaths(Path publicKeyPath, Path privateKeyPath, String algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            KeySpec publicKey = new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath));
            KeySpec privateKey = new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath));
            return new KeyPair(keyFactory.generatePublic(publicKey), keyFactory.generatePrivate(privateKey));
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw Throwables.propagate(e);
        }
    }
}
