package Seguridad;

import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class CifradoAsimetrico {
	
	private final static String ALGO="RSA"; 

	public byte[] cifrar(String mensaje, PublicKey i) { 

		try { 
			Cipher cipher = Cipher.getInstance(ALGO); 
			byte [] clearText = mensaje.getBytes(); 		 
			cipher.init(Cipher.ENCRYPT_MODE, i); 
			byte [] cipheredText = cipher.doFinal(clearText); 
			return cipheredText; 
		} 
		catch (Exception e) { 
			System.out.println("Excepcion: " + e.getMessage()); 
			return null; 
		} 
	} 

	public byte[] descifrar(byte[] cipheredText, KeyPair keyP) { 

		try { 
			Cipher cipher = Cipher.getInstance(ALGO); 
			cipher.init(Cipher.DECRYPT_MODE, keyP.getPrivate()); 
			byte [] clearText = cipher.doFinal(cipheredText); 
			return clearText; 
		}
		catch (Exception e) { 
			System.out.println("Excepcion Asimetrico: " + e.getMessage());
			return null;
		} 

	} 

	public byte[] cifrarConKeyP(String mensaje, PublicKey desKeyP ) {
		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(ALGO);
			String pwd = mensaje;
			byte [] clearText = pwd.getBytes();

			cipher.init(Cipher.ENCRYPT_MODE, desKeyP);
			cipheredText = cipher.doFinal(clearText);
			new String (cipheredText);

		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
		return cipheredText;
	}

}
