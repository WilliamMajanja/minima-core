package org.minima.utils.encrypt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class GenerateKey {

	public static final String 	ASYMETRIC_ALGORITHM_GEN = "RSA";
	public static final String 	ASYMETRIC_ALGORITHM 	= "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	
	private static final String SYMETRIC_ALGORITHM_GEN  = "AES";
	private static final String SYMETRIC_ALGORITHM  	= "AES/GCM/NoPadding";
	
	private static final String SYMETRIC_PASSWORD_ALGORITHM  = "PBKDF2WithHmacSHA256";
	
	public static KeyPair generateKeyPair() throws Exception {

		SecureRandom random 	= new SecureRandom();
		
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096, random);
        
        KeyPair generateKeyPair = keyGen.generateKeyPair();
        
        return generateKeyPair;
    }
	
	public static PublicKey convertBytesToPublic(byte[] zPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		
		KeyFactory kf 			= KeyFactory.getInstance("RSA");
		PublicKey publicKey 	= kf.generatePublic(new X509EncodedKeySpec(zPublicKey));
		
		return publicKey;
	}
	
	public static PrivateKey convertBytesToPrivate(byte[] zPrivateKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		
		KeyFactory kf 			= KeyFactory.getInstance("RSA");
		PrivateKey privateKey 	= kf.generatePrivate(new PKCS8EncodedKeySpec(zPrivateKey));
		
		return privateKey;
	}
	
	public static byte[] secretKey() throws Exception {
    	
		KeyGenerator generator = KeyGenerator.getInstance("AES");
    	generator.init(256);
    	
    	SecretKey secKey = generator.generateKey();
    	
    	byte[] secret = secKey.getEncoded();
    	
    	return secret;
    }
	
	public static SecretKey convertSecret(byte[] zSecret) {
		return new SecretKeySpec(zSecret, "AES");
	}
	
	public static SecretKey secretKey(String zPassword, byte[] zSalt) throws Exception {
    	
		SecretKeyFactory factory 	= SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec 				= new PBEKeySpec(zPassword.toCharArray(), zSalt, 65536, 256);
		SecretKey tmp 				= factory.generateSecret(spec);
		SecretKey secret 			= new SecretKeySpec(tmp.getEncoded(), "AES");
    	
    	return secret;
    }
	
	public static byte[] IvParam() throws Exception {
    	
		SecureRandom random 	= new SecureRandom();
		byte[] ivBytes 			= new byte[12];
		random.nextBytes(ivBytes);
    	
    	return ivBytes;
    }
	
	public static Cipher getAsymetricCipher() throws Exception {
		return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
	}
	
	public static Cipher getSymetricCipher() throws Exception {
		return Cipher.getInstance("AES/GCM/NoPadding");
	}
	
	public static Cipher getCipherSYM(int zCipherMode, byte[] zIvParam, byte[] zSecretKey) throws Exception {
    	
		byte[] ivBytes;
		if (zIvParam == null) {
			ivBytes = IvParam();
		} else {
			ivBytes = zIvParam;
		}
		if (ivBytes.length != 12) {
			byte[] trimmed = new byte[12];
			System.arraycopy(ivBytes, 0, trimmed, 0, Math.min(ivBytes.length, 12));
			ivBytes = trimmed;
		}
		SecretKey sk 		= GenerateKey.convertSecret(zSecretKey);    	
		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
    	
		Cipher aesCipher 	= GenerateKey.getSymetricCipher();
		aesCipher.init(zCipherMode, sk, gcmSpec);
		
    	return aesCipher;
    }
}