package br.hol.signer.security;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESCrypto {

	private static String CIPHER_NAME = "AES/CBC/PKCS5PADDING";

	private static int CIPHER_KEY_LEN = 16; // 128 bits

	private static final Logger L = LoggerFactory.getLogger(AESCrypto.class);

	public static String encrypt(String key, String iv, String data) {

		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
			SecretKeySpec secretKey = new SecretKeySpec(fixKey(key).getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance(AESCrypto.CIPHER_NAME);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			byte[] encryptedData = cipher.doFinal((data.getBytes()));

			String encryptedDataInBase64 = Base64.getEncoder().encodeToString(encryptedData);

			String ivInBase64 = Base64.getEncoder().encodeToString(iv.getBytes("UTF-8"));

			return encryptedDataInBase64 + ":" + ivInBase64;

		} catch (Exception ex) {
			L.error("encrypt: with error");
			throw new RuntimeException(ex);
		}
	}

	private static String fixKey(String key) {

		if (key.length() < AESCrypto.CIPHER_KEY_LEN) {
			int numPad = AESCrypto.CIPHER_KEY_LEN - key.length();

			for (int i = 0; i < numPad; i++) {
				key += "0";
			}
			return key;
		}

		if (key.length() > AESCrypto.CIPHER_KEY_LEN) {
			return key.substring(0, CIPHER_KEY_LEN);
		}

		return key;
	}

	public static String decrypt(String key, String data) {

		try {
			String[] parts = data.split(":");
			IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(parts[1]));
			SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			Cipher cipher = Cipher.getInstance(AESCrypto.CIPHER_NAME);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			byte[] decodedEncryptedData = Base64.getDecoder().decode(parts[0]);
			byte[] original = cipher.doFinal(decodedEncryptedData);
			return new String(original);
		} catch (Exception ex) {
			L.error("decrypt: with error");
			throw new RuntimeException(ex);
		}
	}

}
