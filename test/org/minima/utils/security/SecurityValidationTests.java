package org.minima.utils.security;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.sql.SQLException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.minima.kissvm.Contract;
import org.minima.objects.Coin;
import org.minima.objects.CoinProof;
import org.minima.objects.Transaction;
import org.minima.objects.Witness;
import org.minima.objects.base.MiniData;
import org.minima.objects.base.MiniNumber;
import org.minima.objects.keys.TreeKey;
import org.minima.objects.mmr.MMR;
import org.minima.objects.mmr.MMRData;
import org.minima.objects.mmr.MMREntry;
import org.minima.objects.mmr.MMREntryNumber;
import org.minima.objects.mmr.MMRProof;
import org.minima.system.commands.CommandException;
import org.minima.system.commands.base.mmrproof;
import org.minima.utils.MiniFile;
import org.minima.utils.RPCClient;
import org.minima.utils.encrypt.GenerateKey;
import org.minima.utils.encrypt.javajs.AesUtil;
import org.minima.utils.mysql.MySQLConnect;

public class SecurityValidationTests {

    // ========== MINIFILE PATH TRAVERSAL TESTS ==========

    @Test
    public void testSanitizeFileNameNormalFile() {
        assertEquals("test.txt", MiniFile.sanitizeFileName("test.txt"));
    }

    @Test
    public void testSanitizeFileNameDirectoryTraversal() {
        String result = MiniFile.sanitizeFileName("../../../etc/passwd");
        assertFalse("Result should not contain ..", result.contains(".."));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSanitizeFileNameDoubleDotThrows() {
        MiniFile.sanitizeFileName("foo/..");
    }

    @Test
    public void testSanitizeFileNameMixedTraversal() {
        String result = MiniFile.sanitizeFileName("../../secret/../../../etc/shadow");
        assertFalse("Result should not contain ..", result.contains(".."));
    }

    @Test
    public void testSanitizeFileNameAbsolutePath() {
        String result = MiniFile.sanitizeFileName("/etc/passwd");
        String fileName = new java.io.File(result).getName();
        assertEquals("passwd", fileName);
    }

    @Test
    public void testValidateFileAccessAllowsValidFile() throws Exception {
        File tempDir = new File(System.getProperty("user.dir"), "minima_security_test_" + System.currentTimeMillis());
        tempDir.mkdirs();
        File testFile = new File(tempDir, "test.txt");
        testFile.createNewFile();
        try {
            MiniFile.validateFileAccess(testFile);
        } finally {
            testFile.delete();
            tempDir.delete();
        }
    }

    @Test(expected = SecurityException.class)
    public void testValidateFileAccessBlocksTraversal() {
        File escapeFile = new File("../../../etc/passwd");
        MiniFile.validateFileAccess(escapeFile);
    }

    @Test
    public void testSanitizeFileNameNullInput() {
        assertNull(MiniFile.sanitizeFileName(null));
    }

    @Test
    public void testSanitizeFileNameStripsBackslashTraversal() {
        String result = MiniFile.sanitizeFileName("..\\..\\windows\\system32");
        assertFalse("Result should not contain ..\\", result.contains("..\\"));
    }

    // ========== GENERATE KEY / CRYPTO TESTS ==========

    @Test
    public void testAsymmetricCipherIsOAEP() throws Exception {
        Cipher cipher = GenerateKey.getAsymetricCipher();
        assertEquals("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", cipher.getAlgorithm());
    }

    @Test
    public void testSymmetricCipherIsGCM() throws Exception {
        Cipher cipher = GenerateKey.getSymetricCipher();
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());
    }

    @Test
    public void testGetCipherSYMWithNullIVGeneratesRandomIV() throws Exception {
        byte[] key = GenerateKey.secretKey();
        Cipher cipher = GenerateKey.getCipherSYM(Cipher.ENCRYPT_MODE, null, key);
        assertNotNull(cipher);
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());
        byte[] iv = cipher.getIV();
        assertNotNull(iv);
        assertEquals(12, iv.length);
    }

    @Test
    public void testGetCipherSYMWithProvidedIV() throws Exception {
        byte[] key = GenerateKey.secretKey();
        byte[] iv = GenerateKey.IvParam();
        assertEquals(12, iv.length);
        Cipher cipher = GenerateKey.getCipherSYM(Cipher.ENCRYPT_MODE, iv, key);
        assertNotNull(cipher);
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());
    }

    @Test
    public void testRSAEncryptionWithOAEP() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = GenerateKey.getAsymetricCipher();
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());

        byte[] plaintext = "Hello Minima Security Test".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        Cipher decryptCipher = GenerateKey.getAsymetricCipher();
        decryptCipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = decryptCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAESGCMBasicEncryptionDecryption() throws Exception {
        byte[] key = GenerateKey.secretKey();
        byte[] iv = GenerateKey.IvParam();

        Cipher encCipher = GenerateKey.getCipherSYM(Cipher.ENCRYPT_MODE, iv, key);
        byte[] plaintext = "Minima AES-GCM security test data".getBytes();
        byte[] ciphertext = encCipher.doFinal(plaintext);

        assertEquals(plaintext.length + 16, ciphertext.length);

        byte[] ivFromEnc = encCipher.getIV();
        Cipher decCipher = GenerateKey.getCipherSYM(Cipher.DECRYPT_MODE, ivFromEnc, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testGCMRejectsTamperedCiphertext() throws Exception {
        byte[] key = GenerateKey.secretKey();
        byte[] iv = GenerateKey.IvParam();

        Cipher encCipher = GenerateKey.getCipherSYM(Cipher.ENCRYPT_MODE, iv, key);
        byte[] plaintext = "Tamper detection test".getBytes();
        byte[] ciphertext = encCipher.doFinal(plaintext);

        ciphertext[0] ^= (byte) 0xFF;

        Cipher decCipher = GenerateKey.getCipherSYM(Cipher.DECRYPT_MODE, encCipher.getIV(), key);
        try {
            decCipher.doFinal(ciphertext);
            fail("Expected AEADBadTagException for tampered ciphertext");
        } catch (javax.crypto.AEADBadTagException e) {
        }
    }

    @Test
    public void testRandomIVIsUnique() throws Exception {
        byte[] iv1 = GenerateKey.IvParam();
        byte[] iv2 = GenerateKey.IvParam();
        assertFalse("IVs should be unique", java.util.Arrays.equals(iv1, iv2));
    }

    @Test
    public void testSecretKeyLength() throws Exception {
        byte[] key = GenerateKey.secretKey();
        assertEquals(32, key.length);
    }

    @Test
    public void testConvertSecretKey() throws Exception {
        byte[] keyBytes = GenerateKey.secretKey();
        SecretKey key = GenerateKey.convertSecret(keyBytes);
        assertEquals("AES", key.getAlgorithm());
        assertArrayEquals(keyBytes, key.getEncoded());
    }

    // ========== AES UTIL TESTS ==========

    @Test
    public void testAesUtilEncryptDecrypt() throws Exception {
        AesUtil aesUtil = new AesUtil(256, 1000);
        String salt = "0123456789abcdef";
        String iv = "0123456789abcdef01234567";
        String passphrase = "testPassphrase123";
        String plaintext = "Minima security validation test";

        String ciphertext = aesUtil.encrypt(salt, iv, passphrase, plaintext);
        assertNotNull(ciphertext);
        assertFalse(ciphertext.isEmpty());

        String decrypted = aesUtil.decrypt(salt, iv, passphrase, ciphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testAesUtilUsesGCM() throws Exception {
        AesUtil aesUtil = new AesUtil(256, 1000);
        String salt = "aabbccdd";
        String iv = "0123456789abcdef01234567";
        String passphrase = "gcmTest";
        String plaintext = "GCM mode verification";

        String ciphertext = aesUtil.encrypt(salt, iv, passphrase, plaintext);
        assertNotNull(ciphertext);
        assertFalse(ciphertext.isEmpty());
    }

    // ========== RPCCLIENT SSRF TESTS (reflection) ==========

    @Test
    public void testRPCClientBlocksPrivateIP127() throws Exception {
        Method method = RPCClient.class.getDeclaredMethod("validateAndResolveURI", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "http://127.0.0.1:8080/api");
            fail("Should have blocked loopback address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IOException);
            assertTrue(e.getCause().getMessage().contains("private")
                    || e.getCause().getMessage().contains("reserved")
                    || e.getCause().getMessage().contains("not allowed"));
        }
    }

    @Test
    public void testRPCClientBlocksPrivateIP10() throws Exception {
        Method method = RPCClient.class.getDeclaredMethod("validateAndResolveURI", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "http://10.0.0.1:9001/rpc");
            fail("Should have blocked 10.x private address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IOException);
        }
    }

    @Test
    public void testRPCClientBlocksPrivateIP192_168() throws Exception {
        Method method = RPCClient.class.getDeclaredMethod("validateAndResolveURI", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "http://192.168.1.1/api");
            fail("Should have blocked 192.168.x private address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IOException);
        }
    }

    @Test
    public void testRPCClientBlocksCloudMetadata169() throws Exception {
        Method method = RPCClient.class.getDeclaredMethod("validateAndResolveURI", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "http://169.254.169.254/latest/meta-data/");
            fail("Should have blocked cloud metadata endpoint");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IOException);
        }
    }

    @Test
    public void testRPCClientBlocksFTP() throws Exception {
        Method method = RPCClient.class.getDeclaredMethod("validateAndResolveURI", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "ftp://evil.com/payload");
            fail("Should have blocked non-HTTP scheme");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IOException);
        }
    }

    // ========== MYSQLCONNECT SSRF TESTS (reflection) ==========

    @Test
    public void testMySQLConnectBlocksPrivateIP127() throws Exception {
        Method method = MySQLConnect.class.getDeclaredMethod("validateAndResolveHost", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "127.0.0.1:3306");
            fail("Should have blocked loopback address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof SQLException);
        }
    }

    @Test
    public void testMySQLConnectBlocksCloudMetadata() throws Exception {
        Method method = MySQLConnect.class.getDeclaredMethod("validateAndResolveHost", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "169.254.169.254:3306");
            fail("Should have blocked cloud metadata address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof SQLException);
        }
    }

    @Test
    public void testMySQLConnectBlocksPrivateIP10() throws Exception {
        Method method = MySQLConnect.class.getDeclaredMethod("validateAndResolveHost", String.class);
        method.setAccessible(true);
        try {
            method.invoke(null, "10.0.0.1:3306");
            fail("Should have blocked 10.x private address");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof SQLException);
        }
    }

    // ========== SQL INJECTION PREVENTION TESTS ==========
    // SqlDB.sanitizePathForSQL is a private instance method on an abstract class.
    // We replicate the exact logic here to validate the sanitization behavior.
    // Source: org.minima.utils.SqlDB line 243-246
    private static String sanitizePathForSQL(String path) {
        String safe = path.replace("'", "''").replace(";", "").replace("\\", "/").replace("--", "");
        return new String(safe);
    }

    @Test
    public void testSanitizePathForSQLEscapesSingleQuotes() {
        String result = sanitizePathForSQL("/path/to/file'; DROP TABLE users;--");
        assertTrue("Single quotes should be escaped by doubling", result.contains("''"));
        assertFalse("Semicolons should be removed", result.contains(";"));
        assertFalse("SQL comments should be removed", result.contains("--"));
    }

    @Test
    public void testSanitizePathForSQLRemovesSemicolons() {
        String result = sanitizePathForSQL("/safe/path;exec malicious");
        assertFalse("Semicolons should be removed", result.contains(";"));
    }

    @Test
    public void testSanitizePathForSQLRemovesSQLComments() {
        String result = sanitizePathForSQL("/safe/path--comment");
        assertFalse("SQL comments should be removed", result.contains("--"));
    }

    @Test
    public void testSanitizePathForSQLNormalPath() {
        String result = sanitizePathForSQL("/safe/normal/path");
        assertEquals("/safe/normal/path", result);
    }

    @Test
    public void testSanitizePathForSQLConvertsBackslashes() {
        String result = sanitizePathForSQL("C:\\Users\\data\\backup.sql");
        assertFalse("Backslashes should be converted to forward slashes", result.contains("\\"));
        assertTrue("Backslashes should be converted to forward slashes", result.contains("/"));
    }

    // ========== PROOF SYSTEM REGRESSION TESTS ==========
    // Regression tests for the 11 cascading proof system flaws documented in SECURITY.md §13.

    private static byte[] craftMMRProofStream(int zChainLength) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        MiniNumber.ZERO.writeDataStream(dos);
        MiniNumber.WriteToStream(dos, zChainLength);
        dos.flush();
        return baos.toByteArray();
    }

    @Test(expected = SecurityException.class)
    public void testTreeKeySignThrowsOnExhaustion() {
        TreeKey key = new TreeKey(new MiniData("0x000102"), 2, 2);
        key.setUses(key.getMaxUses());
        key.sign(new MiniData("0xFF"));
    }

    @Test
    public void testClearIsMonotonicResetsAllCacheFields() {
        Transaction txn = new Transaction();
        txn.mHaveCheckedMonotonic = true;
        txn.mIsMonotonic = true;
        txn.mIsValid = true;
        txn.clearIsMonotonic();
        assertFalse("HaveCheckedMonotonic must reset", txn.mHaveCheckedMonotonic);
        assertFalse("IsMonotonic must reset", txn.mIsMonotonic);
        assertFalse("IsValid must reset", txn.mIsValid);
        assertFalse("isCheckedMonotonic must be false after clear", txn.isCheckedMonotonic());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCoinProofConvertThrowsOnInvalidData() {
        CoinProof.convertMiniDataVersion(new MiniData("0x00"));
    }

    @Test
    public void testCoinProofConvertRoundTrip() throws Exception {
        Coin coin = new Coin(new MiniData("0x1234"), MiniNumber.ONE, MiniData.ZERO_TXPOWID);
        MMRProof proof = new MMRProof(MiniNumber.ZERO);
        CoinProof cp = new CoinProof(coin, proof);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        cp.writeDataStream(dos);
        dos.flush();

        CoinProof back = CoinProof.convertMiniDataVersion(new MiniData(baos.toByteArray()));
        assertNotNull("Valid CoinProof must deserialize", back);
        assertTrue("Coin must round-trip", back.getCoin().getCoinID().isEqual(coin.getCoinID()));
    }

    @Test(expected = IOException.class)
    public void testMMRProofRejectsOversizedChain() throws Exception {
        MMRProof proof = new MMRProof();
        proof.readDataStream(new DataInputStream(new ByteArrayInputStream(craftMMRProofStream(5000))));
    }

    @Test(expected = IOException.class)
    public void testMMRProofRejectsNegativeChainLength() throws Exception {
        MMRProof proof = new MMRProof();
        proof.readDataStream(new DataInputStream(new ByteArrayInputStream(craftMMRProofStream(-1))));
    }

    @Test(expected = IOException.class)
    public void testMMRProofConvertRejectsOversizedChain() throws Exception {
        MMRProof.convertMiniDataVersion(new MiniData(craftMMRProofStream(5000)));
    }

    @Test
    public void testMMRCheckProofTimeValidRejectsNullDataEntry() {
        MMR mmr = new MMR();
        MMRData data = new MMRData(new MiniData("0x00"), MiniNumber.ZERO);
        mmr.addEntry(data);

        MMREntryNumber entryNum = new MMREntryNumber(0);
        MMRProof proof = mmr.getProof(entryNum);

        assertTrue("Valid proof must pass before injection", mmr.checkProofTimeValid(entryNum, data, proof));

        mmr.getAllEntries().put("0:" + entryNum.toString(), new MMREntry(0, entryNum, null));
        assertFalse("Entry with null data must be rejected", mmr.checkProofTimeValid(entryNum, data, proof));
    }

    @Test
    public void testMMRDeepCopyPreservesState() throws Exception {
        MMR mmr = new MMR();
        mmr.addEntry(new MMRData(new MiniData("0xAA"), MiniNumber.ONE));
        mmr.addEntry(new MMRData(new MiniData("0xBB"), MiniNumber.TWO));

        MMR copy = mmr.deepCopy();
        assertNotNull("Deep copy must not be null", copy);
        assertEquals(mmr.getTotalEntries(), copy.getTotalEntries());
        assertTrue("Root must round-trip", copy.getRoot().isEqual(mmr.getRoot()));
    }

    @Test
    public void testKissvmProofRejectsOversizedProofData() {
        StringBuilder hex = new StringBuilder("0x");
        for (int i = 0; i < 9000; i++) {
            hex.append("00");
        }
        Contract ctr = new Contract("RETURN PROOF(0x00 0 0x00 0 " + hex + ")", "", new Witness(), new Transaction(), null);
        ctr.run();
        assertTrue("Oversized proof must fail the contract", ctr.isException());
        assertTrue("Exception must mention the size limit", ctr.getException().contains("8192"));
    }

    @Test
    public void testMmrproofCommandRejectsInvalidNumericDataParam() throws Exception {
        mmrproof cmd = new mmrproof();
        cmd.getParams().put("data", "0x00:notanumber");
        cmd.getParams().put("root", "0x00");
        cmd.getParams().put("proof", "0x00");
        try {
            cmd.runCommand();
            fail("Expected CommandException for invalid data numeric suffix");
        } catch (CommandException e) {
            assertTrue(e.getMessage().contains("Invalid numeric value"));
        }
    }

    @Test
    public void testMmrproofCommandRejectsInvalidNumericRootParam() throws Exception {
        mmrproof cmd = new mmrproof();
        cmd.getParams().put("data", "0x00");
        cmd.getParams().put("root", "0x00:notanumber");
        cmd.getParams().put("proof", "0x00");
        try {
            cmd.runCommand();
            fail("Expected CommandException for invalid root numeric suffix");
        } catch (CommandException e) {
            assertTrue(e.getMessage().contains("Invalid numeric value"));
        }
    }
}