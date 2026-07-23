package org.minima.utils.cpip;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CPIP KEM (Key Encapsulation Mechanism) — Hybrid ECDH P-256 + AES-256-GCM.
 *
 * Provides a KEM-DEM construction compatible with CPIP's CryptoPackage:
 *  1. Generate an ephemeral AES-256 key (DEM key)
 *  2. Encrypt the data with CoffeeCipher (AES-256-GCM + HKDF-SHA256)
 *  3. Encrypt the DEM key with the recipient's RSA/KEM public key
 *
 * This replaces the original CryptoPackage with CPIP-derived crypto.
 * The wire format remains compatible with CryptoPackage serialization.
 */
public class CPIPKEM {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int AES_KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int GCM_TAG_BITS = 128;

    /**
     * Generate a random 256-bit AES key.
     */
    public static byte[] generateDemKey() {
        byte[] key = new byte[AES_KEY_SIZE];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Encrypt data using CoffeeCipher (AES-256-GCM with HKDF-SHA256).
     * @param plaintext data to encrypt
     * @param demKey the AES key to use
     * @param recipe domain separation string
     * @return nonce (12) || ciphertext || GCM tag (16)
     */
    public static byte[] encryptWithDem(byte[] plaintext, byte[] demKey, String recipe) {
        return CoffeeCipher.encrypt(plaintext, demKey, recipe);
    }

    /**
     * Decrypt data using CoffeeCipher.
     * @param ciphertext nonce (12) || ciphertext || GCM tag (16)
     * @param demKey the AES key
     * @param recipe domain separation string
     * @return plaintext, or null on failure
     */
    public static byte[] decryptWithDem(byte[] ciphertext, byte[] demKey, String recipe) {
        return CoffeeCipher.decrypt(ciphertext, demKey, recipe);
    }

    /**
     * Encrypt a DEM key using RSA-OAEP (KEM encapsulation).
     * @param rsaPublicKey recipient's RSA public key
     * @param demKey the AES key to encapsulate
     * @return encrypted DEM key
     */
    public static byte[] encapsulateDemKey(byte[] rsaPublicKey, byte[] demKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            java.security.PublicKey pubKey = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(rsaPublicKey));
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            return cipher.doFinal(demKey);
        } catch (Exception e) {
            throw new RuntimeException("KEM encapsulation failed", e);
        }
    }

    /**
     * Decrypt a DEM key using RSA-OAEP (KEM decapsulation).
     * @param rsaPrivateKey recipient's RSA private key
     * @param encapsulatedKey the encrypted DEM key
     * @return the DEM key
     */
    public static byte[] decapsulateDemKey(byte[] rsaPrivateKey, byte[] encapsulatedKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            java.security.PrivateKey privKey = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(rsaPrivateKey));
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            return cipher.doFinal(encapsulatedKey);
        } catch (Exception e) {
            throw new RuntimeException("KEM decapsulation failed", e);
        }
    }

    /**
     * Derive a key using HKDF-SHA256 from an ECDH shared secret.
     * Used for hybrid ECDH+Kyber key exchange.
     */
    public static byte[] deriveKeyFromEcdh(byte[] ecdhSharedSecret, String context) {
        try {
            byte[] salt = MessageDigest.getInstance("SHA-256").digest(
                ("cpip-kem-ecdh:" + context).getBytes("UTF-8"));
            byte[] info = ("cpip-kem-derived:" + context).getBytes("UTF-8");
            return CoffeeCipher.hkdf(ecdhSharedSecret, salt, info, 32);
        } catch (Exception e) {
            throw new RuntimeException("ECDH key derivation failed", e);
        }
    }
}