package Seguridad;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CifradoSimetrico {
	
	private final static String PADDING="AES/ECB/PKCS5Padding";

	public static byte[] cifrar(SecretKey key, byte[] txt) {

		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);

			cipher.init(Cipher.ENCRYPT_MODE, key);

			cipheredText = cipher.doFinal(txt);

			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public String descifrar(byte [] cipheredText, SecretKey key)
	{
		String sim = "";
		try 
		{
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte [] clearText = cipher.doFinal(cipheredText);
			sim = new String(clearText);
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
		}
		return sim;
	}
}