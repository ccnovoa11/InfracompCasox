package Seguridad;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HMAC {
	
	public static byte[] getKeyedDigest(byte[] cedula, SecretKey key, String algoritmo) {
		try {
	        Mac mac = Mac.getInstance(algoritmo);
	        mac.init(key);
	        byte[] bytes = mac.doFinal(cedula);
	        return bytes;
		} catch (Exception e) {
			return null;
		}
	}
}
