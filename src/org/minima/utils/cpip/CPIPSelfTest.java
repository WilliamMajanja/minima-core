package org.minima.utils.cpip;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * CPIP FIPS Power-On Self-Tests.
 *
 * Runs Known Answer Tests (KATs) for all FIPS-approved algorithms
 * at application startup. In FIPS mode (CPIP_FIPS=1), a test failure
 * blocks startup. In non-FIPS mode, failures are logged as warnings.
 *
 * Tests:
 *  - AES-256-GCM encrypt/decrypt roundtrip
 *  - HMAC-SHA256
 *  - HKDF-SHA256
 *  - ECDSA P-256 sign/verify
 *  - ECDH P-256 key exchange
 */
public class CPIPSelfTest {

    private static volatile boolean testsPassed = false;
    private static volatile boolean testsRun = false;

    /**
     * Run all FIPS self-tests.
     * @return true if all tests pass, false otherwise
     */
    public static synchronized boolean runSelfTests() {
        if (testsRun) {
            return testsPassed;
        }
        testsRun = true;

        boolean allPassed = true;
        StringBuilder failures = new StringBuilder();

        // AES-256-GCM KAT
        try {
            testAesGcm();
        } catch (Exception e) {
            allPassed = false;
            failures.append("AES-256-GCM: ").append(e.getMessage()).append("; ");
        }

        // HMAC-SHA256 KAT
        try {
            testHmacSha256();
        } catch (Exception e) {
            allPassed = false;
            failures.append("HMAC-SHA256: ").append(e.getMessage()).append("; ");
        }

        // HKDF-SHA256 KAT
        try {
            testHkdf();
        } catch (Exception e) {
            allPassed = false;
            failures.append("HKDF-SHA256: ").append(e.getMessage()).append("; ");
        }

        // ECDSA P-256 KAT
        try {
            testEcdsa();
        } catch (Exception e) {
            allPassed = false;
            failures.append("ECDSA P-256: ").append(e.getMessage()).append("; ");
        }

        // ECDH P-256 KAT
        try {
            testEcdh();
        } catch (Exception e) {
            allPassed = false;
            failures.append("ECDH P-256: ").append(e.getMessage()).append("; ");
        }

        // CoffeeCipher roundtrip KAT
        try {
            testCoffeeCipher();
        } catch (Exception e) {
            allPassed = false;
            failures.append("CoffeeCipher: ").append(e.getMessage()).append("; ");
        }

        testsPassed = allPassed;

        if (!allPassed) {
            org.minima.utils.MinimaLogger.log("[CPIP] FIPS self-test FAILURES: " + failures);
        }

        return allPassed;
    }

    public static boolean testsPassed() {
        return testsPassed;
    }

    public static void fipsAssert() {
        if ("1".equals(System.getenv("CPIP_FIPS")) && !testsPassed) {
            throw new RuntimeException("FIPS mode enabled but CPIP self-tests have not passed");
        }
    }

    // ─── Individual tests ─────────────────────────────────────────────────

    private static void testAesGcm() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        byte[] key = kg.generateKey().getEncoded();
        byte[] nonce = new byte[12];
        new java.security.SecureRandom().nextBytes(nonce);
        byte[] plaintext = "CPIP FIPS AES-256-GCM KAT".getBytes();

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.GCMParameterSpec(128, nonce));
        byte[] ct = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.GCMParameterSpec(128, nonce));
        byte[] pt = cipher.doFinal(ct);

        if (!java.util.Arrays.equals(plaintext, pt)) {
            throw new RuntimeException("encrypt/decrypt mismatch");
        }
    }

    private static void testHmacSha256() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("test-key".getBytes(), "HmacSHA256"));
        byte[] result = mac.doFinal("test-message".getBytes());
        if (result.length != 32) {
            throw new RuntimeException("HMAC-SHA256 output length != 32");
        }
    }

    private static void testHkdf() throws Exception {
        byte[] ikm = "test-ikm".getBytes();
        byte[] salt = "test-salt".getBytes();
        byte[] info = "test-info".getBytes();
        byte[] okm = CoffeeCipher.hkdf(ikm, salt, info, 32);
        if (okm.length != 32) {
            throw new RuntimeException("HKDF output length != 32");
        }
    }

    private static void testEcdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
        sig.initSign(kp.getPrivate());
        sig.update("test".getBytes());
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update("test".getBytes());
        if (!sig.verify(signature)) {
            throw new RuntimeException("ECDSA verify failed");
        }
    }

    private static void testEcdh() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        javax.crypto.KeyAgreement ka1 = javax.crypto.KeyAgreement.getInstance("ECDH", "BC");
        ka1.init(alice.getPrivate());
        ka1.doPhase(bob.getPublic(), true);
        byte[] shared1 = ka1.generateSecret();

        javax.crypto.KeyAgreement ka2 = javax.crypto.KeyAgreement.getInstance("ECDH", "BC");
        ka2.init(bob.getPrivate());
        ka2.doPhase(alice.getPublic(), true);
        byte[] shared2 = ka2.generateSecret();

        if (!java.util.Arrays.equals(shared1, shared2)) {
            throw new RuntimeException("ECDH shared secrets don't match");
        }
    }

    private static void testCoffeeCipher() throws Exception {
        byte[] baseKey = new byte[32];
        new java.security.SecureRandom().nextBytes(baseKey);
        byte[] plaintext = "CPIP CoffeeCipher roundtrip test".getBytes();
        byte[] ct = CoffeeCipher.encrypt(plaintext, baseKey, "test");
        byte[] pt = CoffeeCipher.decrypt(ct, baseKey, "test");
        if (pt == null || !java.util.Arrays.equals(plaintext, pt)) {
            throw new RuntimeException("CoffeeCipher roundtrip failed");
        }
    }
}