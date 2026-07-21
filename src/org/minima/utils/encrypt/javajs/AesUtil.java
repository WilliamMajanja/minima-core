package org.minima.utils.encrypt.javajs;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.DecoderException;
import org.minima.objects.base.MiniData;

public class AesUtil {
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final int keySize;
    private final int iterationCount;
    private final Cipher cipher;
    
    public AesUtil(int keySize, int iterationCount) {
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw fail(e);
        }
    }
    
    public String decrypt(String salt, String iv, String passphrase, String ciphertext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] ivBytes = hex(iv);
            if (ivBytes.length != GCM_IV_LENGTH) {
                byte[] paddedIv = new byte[GCM_IV_LENGTH];
                System.arraycopy(ivBytes, 0, paddedIv, 0, Math.min(ivBytes.length, GCM_IV_LENGTH));
                ivBytes = paddedIv;
            }
            byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, ivBytes, base64Decode(ciphertext));
            return new String(decrypted, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            return null;
        }catch (Exception e){
            return null;
        }
    }
    
    public String encrypt(String salt, String iv, String passphrase, String plaintext) {
        try {
            SecretKey key = generateKey(salt, passphrase);
            byte[] ivBytes = hex(iv);
            if (ivBytes.length != GCM_IV_LENGTH) {
                byte[] paddedIv = new byte[GCM_IV_LENGTH];
                System.arraycopy(ivBytes, 0, paddedIv, 0, Math.min(ivBytes.length, GCM_IV_LENGTH));
                ivBytes = paddedIv;
            }
            byte[] decrypted = doFinal(Cipher.ENCRYPT_MODE, key, ivBytes, plaintext.getBytes());
            return base64Encode(decrypted);
        
        }catch (Exception e){
            return null;
        }
    }
    
    private byte[] doFinal(int encryptMode, SecretKey key, byte[] ivBytes, byte[] bytes) {
        try {
            cipher.init(encryptMode, key, new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes));
            return cipher.doFinal(bytes);
        }
        catch (Exception e) {
            return null;
        }
    }
    
    private SecretKey generateKey(String salt, String passphrase) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return key;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }

    public static byte[] base64Decode(String str) {
        return Base64.getDecoder().decode(str);
    }
    
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    
    public static byte[] hex(String str) {
        try {
        	return new MiniData(str).getBytes();
//            return Hex.decodeHex(str.toCharArray());
        }
        catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }
    
    private IllegalStateException fail(Exception e) {
        return null;
    }

    public static void main(String[] zArgs) {
    	
    	String text 	= "helloyou!";
    	String password = "apasswordblabla";
    	
    	AesUtil aesUtil = new AesUtil(128, 1000);
    	
    	String ciper = aesUtil.encrypt( "4452150bad3b58e9d2c043ad24db2b1d", 
										"0d93cefd0147ecb48a379b5be0da7e8a", 
										password, 
										text);
    	    	
    	System.out.println(ciper);

    	
    	String plain = aesUtil.decrypt(	"4452150bad3b58e9d2c043ad24db2b1d", 
    									"0d93cefd0147ecb48a379b5be0da7e8a", 
    									password, 
    									ciper);
    	
    	
    	System.out.println(plain);
    	
    }
}