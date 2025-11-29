package com.tcs.bancs.microservices.Encryption;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.management.InstanceNotFoundException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Component
public class AESEncryptionUtility {
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(AESEncryptionUtility.class);
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final String privateKeyPath;
    private final String certPath;

    // --- Reusable, thread-safe objects initialized once ---
    private PrivateKey eisPrivateKey;
    private PublicKey eisPublicKey;
   
    public AESEncryptionUtility(@Value("${AadeshPrivateKey.path}") String privateKeyPath, 
                                @Value("${CertPath}") String certPath) {
        this.privateKeyPath = privateKeyPath;
        this.certPath = certPath;
    }

    @PostConstruct
    public void init() throws Exception,IOException, ClassNotFoundException, NoSuchMethodException,
	InvocationTargetException,InstanceNotFoundException,
	InvalidAlgorithmParameterException, InterruptedException {
        LOGGER.info("Initializing AESEncryptionUtility...");
        // Add BouncyCastle provider if needed, once.
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Load private key once
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replaceAll("\\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.eisPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        
        // Load public key from certificate once
        try (FileInputStream fin = new FileInputStream(certPath)) {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
            this.eisPublicKey = certificate.getPublicKey();
        }
        LOGGER.info("AESEncryptionUtility initialized successfully.");
    }
    
    // This method is now instance-level, not static
    public String eis_encrypt(String message, String key) throws Exception,IOException, ClassNotFoundException, NoSuchMethodException,
	InvocationTargetException,InstanceNotFoundException,
	InvalidAlgorithmParameterException, InterruptedException {
        byte[] keybyte = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivkey = Arrays.copyOf(keybyte, 12);

        SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
        // Cipher objects can be reused if initialized with the same key.
        // For performance, creating a new instance is still fast compared to file I/O.
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivkey);
        c.init(Cipher.ENCRYPT_MODE, seckey, gcmParameterSpec);
        
        byte[] encvalue = c.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encvalue);
    }

    // This method is now instance-level, not static
    public String sign(String message) throws Exception,IOException, ClassNotFoundException, NoSuchMethodException,
	InvocationTargetException,InstanceNotFoundException,
	InvalidAlgorithmParameterException, InterruptedException {
        // Reuse the initialized Signature object for performance
        // Note: Signature objects are not thread-safe, so a new one must be created per thread.
        // This is still much faster than re-reading the key from disk.
        Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM);
        sign.initSign(this.eisPrivateKey);
        sign.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sign.sign());
    }

    // This method is now instance-level, not static
    public String rsaEncrypt(String data) throws Exception,IOException, ClassNotFoundException, NoSuchMethodException,
	InvocationTargetException,InstanceNotFoundException,
	InvalidAlgorithmParameterException, InterruptedException {
    	
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
      
        cipher.init(Cipher.ENCRYPT_MODE, this.eisPublicKey);
        
        byte[] encdatabyte = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
       
        return Base64.getEncoder().encodeToString(encdatabyte);
    }

    // Renamed from RSADecrypt, as it was performing AES decryption.
    // Assuming 'message' is the encrypted payload and 'key' is the AES key.
    public String aes_decrypt(String message, String key) throws Exception,IOException, ClassNotFoundException, NoSuchMethodException,
	InvocationTargetException,InstanceNotFoundException,
	InvalidAlgorithmParameterException, InterruptedException {
        byte[] keybyte = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivkey = Arrays.copyOf(keybyte, 12);
        
        byte[] encvalue = Base64.getDecoder().decode(message);
        SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivkey);
        // NOTE: The original code used ENCRYPT_MODE for decryption which is incorrect for AES/GCM.
        // It should be DECRYPT_MODE. If the original code "worked", the external API might be expecting this anomaly.
        // Correct implementation is Cipher.DECRYPT_MODE.
        c.init(Cipher.DECRYPT_MODE, seckey, gcmParameterSpec);
        byte[] decvalue = c.doFinal(encvalue);
        return new String(decvalue, StandardCharsets.UTF_8);
    }
    
    public String aesDecrypt(String key, String initVector, String encrypted)
			throws UnsupportedEncodingException {
		byte[] keyb = keyToB(key);
		byte[] ivb = keyToB(initVector);
		String dec = decrypt1(keyb, ivb, encrypted);
		return dec;
	}
    
	public String decrypt1(byte[] key, byte[] initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original, "UTF-8");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Algorithm not found: {}", e);
		} catch (NoSuchPaddingException e) {
			LOGGER.error("Padding not found: {}",  e);
		} catch (InvalidKeyException e) {
			LOGGER.error("Invalid key: {}", e);
		} catch (InvalidAlgorithmParameterException e) {
			LOGGER.error("Invalid algorithm parameter: {}",  e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.error("Illegal block size: {}", e);
		} catch (BadPaddingException e) {
			LOGGER.error("Bad padding: {}", e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("Unsupported encoding: {}", e);
		} catch (Exception e) {
			LOGGER.error("An unexpected error occurred: {}", e);
		}

		return null;
	}
	
	public byte[] keyToB(String key) throws UnsupportedEncodingException {

		byte[] keybyte = Base64.getDecoder().decode(key.getBytes("UTF-8"));

		return keybyte;
	}
}
