package org.minima.utils.cpip;

import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * CoffeeCipher v3 — AES-256-GCM (FIPS 197) with HKDF-SHA256 key derivation.
 *
 * Format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
 * Key derivation: HKDF-SHA256 (SP 800-56C) with domain-separated info strings.
 *
 * Interoperable with the Python CPIP CoffeeCipher class:
 *   salt = SHA256(b"\xc0\xff\xee" + recipe)
 *   info = b"cpip-cipher-v3:" + recipe
 *   key = HKDF(base_key, salt, info, 32)
 */
public class CoffeeCipher {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits

    /**
     * HKDF-Extract: HMAC-SHA256(salt, IKM) -> PRK
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (Exception e) {
            throw new RuntimeException("HKDF-Extract failed", e);
        }
    }

    /**
     * HKDF-Expand: HMAC-SHA256 chain -> OKM
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            int n = (length + 31) / 32;
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int offset = 0;
            for (int i = 1; i <= n; i++) {
                mac.reset();
                byte[] input = new byte[t.length + info.length + 1];
                System.arraycopy(t, 0, input, 0, t.length);
                System.arraycopy(info, 0, input, t.length, info.length);
                input[input.length - 1] = (byte) i;
                t = mac.doFinal(input);
                int copyLen = Math.min(32, length - offset);
                System.arraycopy(t, 0, okm, offset, copyLen);
                offset += copyLen;
            }
            return okm;
        } catch (Exception e) {
            throw new RuntimeException("HKDF-Expand failed", e);
        }
    }

    /**
     * Full HKDF (Extract-then-Expand) per SP 800-56C.
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    /**
     * Derive a 32-byte cipher key from a base key and recipe name.
     * salt = SHA256(b"\xc0\xff\xee" + recipe.getBytes())
     * info = b"cpip-cipher-v5:" + recipe.getBytes()
     */
    public static byte[] keyFromRecipe(byte[] baseKey, String recipe) {
        try {
            byte[] recipeBytes = recipe.getBytes("UTF-8");
            byte[] coffeePrefix = new byte[] {(byte) 0xc0, (byte) 0xff, (byte) 0xee};
            byte[] saltInput = new byte[coffeePrefix.length + recipeBytes.length];
            System.arraycopy(coffeePrefix, 0, saltInput, 0, coffeePrefix.length);
            System.arraycopy(recipeBytes, 0, saltInput, coffeePrefix.length, recipeBytes.length);
            byte[] salt = MessageDigest.getInstance("SHA-256").digest(saltInput);

            byte[] infoPrefix = "cpip-cipher-v5:".getBytes("UTF-8");
            byte[] info = new byte[infoPrefix.length + recipeBytes.length];
            System.arraycopy(infoPrefix, 0, info, 0, infoPrefix.length);
            System.arraycopy(recipeBytes, 0, info, infoPrefix.length, recipeBytes.length);

            return hkdf(baseKey, salt, info, 32);
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    /**
     * Encrypt using AES-256-GCM.
     * @param plaintext data to encrypt
     * @param baseKey base key for HKDF derivation
     * @param recipe domain separation string (e.g. "minima")
     * @return nonce (12) || ciphertext || GCM tag (16)
     */
    public static byte[] encrypt(byte[] plaintext, byte[] baseKey, String recipe) {
        try {
            byte[] key = keyFromRecipe(baseKey, recipe);
            byte[] nonce = new byte[NONCE_LENGTH];
            SECURE_RANDOM.nextBytes(nonce);

            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("CoffeeCipher encrypt failed", e);
        }
    }

    /**
     * Decrypt using AES-256-GCM.
     * @param ciphertext nonce (12) || ciphertext || GCM tag (16)
     * @param baseKey base key for HKDF derivation
     * @param recipe domain separation string
     * @return plaintext, or null on authentication failure
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] baseKey, String recipe) {
        if (ciphertext == null || ciphertext.length < NONCE_LENGTH + 16) {
            return null;
        }
        try {
            byte[] key = keyFromRecipe(baseKey, recipe);
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(ciphertext, 0, nonce, 0, NONCE_LENGTH);
            byte[] ctAndTag = new byte[ciphertext.length - NONCE_LENGTH];
            System.arraycopy(ciphertext, NONCE_LENGTH, ctAndTag, 0, ctAndTag.length);

            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            return cipher.doFinal(ctAndTag);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Domain-separated SHA-256 hash (matches Python CoffeeCipher.hash).
     */
    public static String hash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(concat("cpip-hash-v5:".getBytes("UTF-8"), data));
            for (int i = 0; i < 4; i++) {
                h = md.digest(concat(concat("cpip-hash-v5:".getBytes("UTF-8"), h), data));
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : h) {
                hex.append(String.format("%02x", b));
            }
            return hex.substring(0, 16);
        } catch (Exception e) {
            throw new RuntimeException("CoffeeCipher hash failed", e);
        }
    }

    /**
     * Get the default recipe from environment or use "minima".
     */
    public static String getDefaultRecipe() {
        String recipe = System.getenv("CPIP_RECIPE");
        return (recipe != null && !recipe.isEmpty()) ? recipe : "minima";
    }

    /**
     * Get the default base key from environment or generate a random one.
     */
    public static byte[] getDefaultBaseKey() {
        String keyHex = System.getenv("CPIP_COVERT_KEY");
        if (keyHex != null && !keyHex.isEmpty()) {
            return hexToBytes(keyHex);
        }
        byte[] key = new byte[32];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }

    // ─── Utility ──────────────────────────────────────────────────────────

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}