package org.minima.utils.cpip;

import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * CPIP ECDSA P-256 / ECDH P-256 — FIPS 186-4 constant-time ECC.
 *
 * Uses BouncyCastle jdk18on for EC operations. Provides:
 *  - ECDSA P-256 sign/verify (DER-encoded signatures)
 *  - ECDH P-256 key exchange (SHA-256 of shared secret)
 *  - Node identity derivation (coffee: address format)
 *
 * Interoperable with the Python CPIP ECP256 class.
 */
public class CPIPECDSA {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String CURVE_NAME = "secp256r1";

    /**
     * Sign a message with ECDSA P-256 using SHA-256.
     * @param message data to sign
     * @param privateKey private key (PKCS8 encoded)
     * @return DER-encoded signature
     */
    public static byte[] sign(byte[] message, byte[] privateKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            java.security.PrivateKey privKey = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(privateKey));
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA", "BC");
            sig.initSign(privKey, SECURE_RANDOM);
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("ECDSA sign failed", e);
        }
    }

    /**
     * Verify an ECDSA P-256 signature.
     * @param message original data
     * @param signature DER-encoded signature
     * @param publicKey public key (X509 encoded, uncompressed point)
     * @return true if signature is valid
     */
    public static boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            java.security.PublicKey pubKey = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(publicKey));
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA", "BC");
            sig.initVerify(pubKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ECDH P-256 key exchange — derive a 32-byte shared secret.
     * @param ourPrivateKey our private key (PKCS8)
     * @param theirPublicKey their public key (X509)
     * @return SHA-256 of the raw ECDH shared secret (32 bytes)
     */
    public static byte[] keyExchange(byte[] ourPrivateKey, byte[] theirPublicKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            java.security.PrivateKey privKey = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(ourPrivateKey));
            java.security.PublicKey pubKey = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(theirPublicKey));

            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH", "BC");
            ka.init(privKey);
            ka.doPhase(pubKey, true);
            byte[] sharedSecret = ka.generateSecret();
            return MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        } catch (Exception e) {
            throw new RuntimeException("ECDH key exchange failed", e);
        }
    }

    /**
     * Generate an ECDSA P-256 key pair.
     * @return KeyPair for P-256
     */
    public static java.security.KeyPair generateKeyPair() {
        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec(CURVE_NAME), SECURE_RANDOM);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("ECDSA key generation failed", e);
        }
    }

    /**
     * Derive a short coffee: address from a public key.
     * Format: coffee:<base32(SHA256(pk)[:4])>
     */
    public static String pubkeyToAddress(byte[] publicKeyBytes) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(publicKeyBytes);
            byte[] first4 = new byte[4];
            System.arraycopy(hash, 0, first4, 0, 4);
            return "coffee:" + base32Encode(first4).toLowerCase();
        } catch (Exception e) {
            throw new RuntimeException("Address derivation failed", e);
        }
    }

    /**
     * HMAC-SHA256 keyed hash.
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    /**
     * Generate an HMAC-SHA256 RPC token.
     * Format: base64(nodeId:expiry:signature)
     */
    public static String generateRpcToken(String nodeId, byte[] secret, int ttlSeconds) {
        long expiry = System.currentTimeMillis() / 1000 + ttlSeconds;
        String payload = nodeId + ":" + expiry;
        byte[] sig = hmacSha256(secret, payload.getBytes());
        String tokenRaw = payload + ":" + bytesToHex(sig);
        return Base64.getEncoder().encodeToString(tokenRaw.getBytes());
    }

    /**
     * Verify an HMAC-SHA256 RPC token.
     */
    public static boolean verifyRpcToken(String token, String expectedNodeId, byte[] secret) {
        try {
            String decoded = new String(Base64.getDecoder().decode(token));
            String[] parts = decoded.split(":");
            if (parts.length < 3) return false;
            String nodeId = parts[0];
            long expiry = Long.parseLong(parts[1]);
            if (!nodeId.equals(expectedNodeId)) return false;
            if (System.currentTimeMillis() / 1000 > expiry) return false;

            String payload = nodeId + ":" + expiry;
            StringBuilder sigBuilder = new StringBuilder();
            for (int i = 2; i < parts.length; i++) {
                if (i > 2) sigBuilder.append(":");
                sigBuilder.append(parts[i]);
            }
            byte[] expectedSig = hmacSha256(secret, payload.getBytes());
            String expectedHex = bytesToHex(expectedSig);
            return constantTimeEquals(expectedHex, sigBuilder.toString());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract the node ID from an RPC token without verifying.
     */
    public static String extractNodeIdFromToken(String token) {
        try {
            String decoded = new String(Base64.getDecoder().decode(token));
            String[] parts = decoded.split(":");
            return parts.length >= 1 ? parts[0] : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ─── Utility ──────────────────────────────────────────────────────────

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private static String base32Encode(byte[] data) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                result.append(alphabet.charAt(index));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            result.append(alphabet.charAt(index));
        }
        return result.toString();
    }
}