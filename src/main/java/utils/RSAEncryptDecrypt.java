package utils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAEncryptDecrypt {

	public static byte[] encrypt(String original, Key privateKey) {
		if (original != null && privateKey != null) {
			byte[] bs = original.getBytes();
			byte[] encData = convert(bs, privateKey, Cipher.ENCRYPT_MODE);
			return encData;
		}
		return null;
	}

	public static byte[] decrypt(byte[] encrypted, Key publicKey) {
		if (encrypted != null && publicKey != null) {
			byte[] decData = convert(encrypted, publicKey, Cipher.DECRYPT_MODE);
			return decData;
		}
		return null;
	}

	private static byte[] convert(byte[] data, Key key, int mode) {
		try {
			Cipher cipher = Cipher.getInstance(RSAConstants.ALGORITHM);
			cipher.init(mode, key);
			byte[] newData = cipher.doFinal(data);
			return newData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String sign(String plainText, PrivateKey privateKey) throws Exception {
	    Signature privateSignature = Signature.getInstance("SHA256withRSA");
	    privateSignature.initSign(privateKey);
	    privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

	    byte[] signature = privateSignature.sign();

	    return Base64.getEncoder().encodeToString(signature);
	}
	
	public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
	    Signature publicSignature = Signature.getInstance("SHA256withRSA");
	    publicSignature.initVerify(publicKey);
	    publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

	    byte[] signatureBytes = Base64.getDecoder().decode(signature);

	    return publicSignature.verify(signatureBytes);
	}

}