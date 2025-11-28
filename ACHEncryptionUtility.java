package com.tcs.sbi.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.tcs.sbi.launcher.ACHEncryptionLuncher;

public class ACHEncryptionUtility {

	private static final Logger log = LogManager.getLogger(ACHEncryptionLuncher.class);

	/**
	 * PGP Sign and Encrypt a file using Streams (Low Memory Usage). Output is ASCII
	 * Armored (.txt).
	 */
	public static void signAndEncryptFile(InputStream inputStream, OutputStream outputStream, String fileName,
			PGPPublicKey encKey, PGPPrivateKey signKey) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		// 1. Wrap output in ArmoredOutputStream to get .txt (ASCII) output
		try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream)) {

			// 2. Init Encryption Generator (AES-256)
			JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
					.setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC");

			PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

			// 3. Init Compression Generator (ZIP)
			PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			try (
					// Open Encryption Stream
					OutputStream encryptedOut = encryptedDataGenerator.open(armoredOutputStream, new byte[4096]);
					// Open Compression Stream
					OutputStream compressedOut = compressedDataGenerator.open(encryptedOut)) {

				// 4. Init Signature Generator
				PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
						new JcaPGPContentSignerBuilder(signKey.getPublicKeyPacket().getAlgorithm(), PGPUtil.SHA256)
								.setProvider("BC"));

				signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signKey);

				// --- REMOVED USER ID BLOCK HERE (Not required for functionality and was causing error) ---

				// Write One-Pass Signature Header
				signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

				// 5. Init Literal Data Generator (The actual file content)
				PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

				try (OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, fileName,
						new Date(), new byte[4096])) {

					// 6. Read Input File -> Update Signature -> Write to Output
					byte[] buffer = new byte[4096];
					int len;
					while ((len = inputStream.read(buffer)) > 0) {
						literalOut.write(buffer, 0, len);
						signatureGenerator.update(buffer, 0, len);
					}
				}

				// 7. Generate and Append the Signature
				signatureGenerator.generate().encode(compressedOut);
			}

			encryptedDataGenerator.close();
		}
	}

	/**
	 * Convert Standard Java Private Key (from .pfx) to PGP Private Key for Signing.
	 */
	public static PGPPrivateKey getPGPPrivateKeyFromPFX(String pfxPath, String password) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(pfxPath)) {
			ks.load(fis, password.toCharArray());
		}
		String alias = ks.aliases().nextElement();
		java.security.PrivateKey javaPrivateKey = (java.security.PrivateKey) ks.getKey(alias, password.toCharArray());
		java.security.cert.Certificate javaCert = ks.getCertificate(alias);
		java.security.PublicKey javaPublicKey = javaCert.getPublicKey();

		JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL,
				new java.security.KeyPair(javaPublicKey, javaPrivateKey), new Date());

		return pgpKeyPair.getPrivateKey();
	}

	/**
	 * Convert Standard Java Public Certificate (from .cer) to PGP Public Key for Encryption.
	 */
	public static PGPPublicKey getPGPPublicKeyFromCer(String cerPath) throws Exception {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert;
		try (FileInputStream fis = new FileInputStream(cerPath)) {
			cert = certFactory.generateCertificate(fis);
		}
		java.security.PublicKey javaPublicKey = cert.getPublicKey();
		JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
		return converter.getPGPPublicKey(PGPPublicKey.RSA_GENERAL, javaPublicKey, new Date());
	}

	// --- Existing Helpers ---

	public static String aesDecrypt(String key, String initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(keyToB(initVector));
			SecretKeySpec skeySpec = new SecretKeySpec(keyToB(key), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original, "UTF-8");
		} catch (Exception e) {
			log.error("Decrypt Error: " + e.getMessage());
		}
		return null;
	}

	public static byte[] keyToB(String key) throws UnsupportedEncodingException {
		return Base64.getDecoder().decode(key.getBytes("UTF-8"));
	}

	public static boolean extensionValidation(String input) {
		String fileExtension = FilenameUtils.getExtension(input);
		return "txt".equalsIgnoreCase(fileExtension);
	}

	public static String generateRefrenceNumber() {
		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		return "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);
	}

	public static Timestamp getTimestamp() {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
			String strTime = sdf.format(new Date());
			return Timestamp.valueOf(strTime);
		} catch (Exception e) {
			return null;
		}
	}
	
	public static int returnMaxDays(int calMonth) {
		if (calMonth == 2) return 28; 
		if (calMonth == 4 || calMonth == 6 || calMonth == 9 || calMonth == 11) return 30;
		return 31;
	}
}
