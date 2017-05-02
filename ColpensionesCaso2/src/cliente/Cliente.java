package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import Seguridad.Certificado;
import Seguridad.CifradoAsimetrico;
import Seguridad.CifradoSimetrico;
import Seguridad.HMAC;
import util.Hex;

public class Cliente extends Thread{

	//Protocolo inicial
	
	private final static String HOLA = "HOLA";
	private final static String OK = "OK";
	private final static String ERROR = "ERROR";
	private final static String SEPARADOR = ":";

	// Constantes de algoritmos

	// Algoritmos de tipo Simetrico (ALGs) - Valores posibles: DES, AES, Blowfish, RC4
	// Algoritmos de tipo Asimetricos (ALGa) - Valores posibles: RSA
	// Algoritmos de tipo HMAC (ALGh) - Valores posibles: HMACMD5, HMACSHA1, HMACSHA256

	private final static String ALGS = "AES";
	private final static String ALGA = "RSA";
	private final static String ALGH = "HMACMD5";
	private final static String ALGORITMOS = "ALGORITMOS"+SEPARADOR+ALGS+SEPARADOR+ALGA+SEPARADOR+ALGH;

	// Variables de conexion
	private final static String IP = "172.24.42.40";
	private final static int PUERTO = 4443;
	private static Socket socket;

	// Variables de consola
	private PrintWriter out;
	private BufferedReader in;
	
	//Variables de seguridad
	private  Certificado certificado;
	private  X509Certificate servidor;
	private  KeyPair keys;
	private  PublicKey llavePublicaServidor;
	private  SecretKey llaveSimetrica;
	private  CifradoAsimetrico cifradoAsimetrico;
	private  CifradoSimetrico cifradoSimetrico;
	private  HMAC hmac;
	private  Hex converter;
	
	
	public void inicializar(){
		certificado = new Certificado();
		cifradoSimetrico = new CifradoSimetrico();
		cifradoAsimetrico = new CifradoAsimetrico();
		hmac = new HMAC();
		converter = new Hex();
		try 
		{	
			socket = new Socket(IP, PUERTO);
			out = new PrintWriter(socket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader( socket.getInputStream()));
		}
		catch (Exception e) 
		{
			System.err.println("Error en la inicializacion de variables: "+ e); 
		}
	}
	
	public Cliente(){
		inicializar();;
		iniciarComunicacion();
		try {
			intercambioCD();
			autenticacion();
			consulta();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		cerrarConexiones();
	}
	public static void main(String[] args) throws IOException{
		new Cliente();
	}
	
	public void iniciarComunicacion(){
		try{
			out.println(HOLA);
			String rta = in.readLine();

			if (rta.equals(OK))
			{
				out.println(ALGORITMOS);
			}
		}
		catch (Exception e)
		{
			System.err.println("ERROR - ETAPA1: inicio de sesion");
		}
	}
	
	public void intercambioCD() throws IOException{
		String respuesta = in.readLine();
		if(respuesta.equals(OK)){
			try{
				String ct = certificado.create(new Date(), new Date(), "RSA", 512, "SHA1withRSA");
				keys = certificado.getKeys();
				out.println(ct);
				String pem = leerCertificado(in);
				verificarCertificado(pem);
				llavePublicaServidor = servidor.getPublicKey();
			}
			catch(Exception e){
				System.out.println("ERROR - Etapa 2: Intercambio de CD");
			}
		}
		else if(respuesta.equals(ERROR))
		{
			System.out.println("ERROR EN EL SERVIDOR");
		}	
	}
	
	public void autenticacion() throws IOException{
		
		//----------------RETO 1----------------------------------------------------------------
		//Cifrado reto 1
		int numReto = (int) (Math.random()*100);
		String reto1 = Integer.toString(numReto);
		byte[] cifradoReto1 = cifradoAsimetrico.cifrar(reto1, llavePublicaServidor);
		String reto1Enviar = converter.transformarHEX(cifradoReto1);
		out.println(reto1Enviar);
		long indior1 = System.currentTimeMillis();
		//Descifrado reto 1
		in.readLine(); //vacío
		String reto1server = in.readLine();
		long indior2 = System.currentTimeMillis();
		long indicador1 = indior2-indior1;
<<<<<<< HEAD
		System.out.println("TIEMPO AUTENTICACIÓN DEL SERVIDOR: "+indicador1);
=======
		System.out.println("INDICADOR SERVIDOR: "+indicador1);
>>>>>>> origin/master
		byte[] sreto1 = converter.destransformarHEX(reto1server);
		byte[] descifradoReto1 = cifradoAsimetrico.descifrar(sreto1, keys);
		String servidornum = new String(descifradoReto1);
		if(reto1.equals(servidornum)){
			out.println(OK);
		}else{
			out.println(ERROR);
		}
		
		//---------------RETO 2--------------------------------------------------------------------
		//Descifrado reto 2
		String reto2 = in.readLine();
		byte[] byreto2 = converter.destransformarHEX(reto2);
		byte[] descifradoReto2 = cifradoAsimetrico.descifrar(byreto2, keys);
		String streto2 = new String(descifradoReto2);
		//cifrado reto 2
		byte[] cifrarReto2 = cifradoAsimetrico.cifrar(streto2, llavePublicaServidor);
		String reto2cifrado = converter.transformarHEX(cifrarReto2);
		out.println(reto2cifrado);
	}
	
	public void consulta() throws IOException{
		
		//LLAVE SIMÉTRICA
		String llavesim = in.readLine();
		byte[] desllavesim = converter.destransformarHEX(llavesim);
		byte[] simkey = cifradoAsimetrico.descifrar(desllavesim, keys);
		SecretKeySpec sk = new SecretKeySpec(simkey, ALGS);
		llaveSimetrica = sk;
		
		//Cifrado del mensaje
		int id = (int) (Math.random()*100)+1;
		String cc = Integer.toString(id);
		byte[] bcedula = converter.destransformarHEX(cc);
		byte[] cedula = cifradoSimetrico.cifrar(llaveSimetrica,bcedula);
		
		//Digest
		byte[] hashcedula = hmac.getKeyedDigest(bcedula, llaveSimetrica, ALGH);
		byte[] chashcedula = cifradoSimetrico.cifrar(llaveSimetrica, hashcedula);
		
		String ccedula  = converter.transformarHEX(cedula);
		String hcedula = converter.transformarHEX(chashcedula);
		String mensaje = ccedula + SEPARADOR + hcedula;
		out.println(mensaje);
<<<<<<< HEAD
		long indc3 = System.currentTimeMillis();
=======
		
>>>>>>> origin/master
		//Descifrar respuesta
		String[] rta = in.readLine().split(SEPARADOR);
		long indc23 = System.currentTimeMillis();
		long indicador3 = indc23 - indc3;
		System.out.println("TIEMPO DE CONSULTA: "+indicador3);
		
		byte[] ccrta = converter.destransformarHEX(rta[0]);
		byte[] hashrta = converter.destransformarHEX(rta[1]);
		String desccrta = cifradoSimetrico.descifrar(ccrta, llaveSimetrica);
		String deshashrta = cifradoSimetrico.descifrar(hashrta, llaveSimetrica);
		
		if(desccrta.equals("Este mensaje es la respuesta a su consulta")){
			out.println(OK);
		}
	}
	
	public String leerCertificado(BufferedReader pIn) throws IOException{
		String pem = "";
		String certificado = pIn.readLine();
		if(certificado.equalsIgnoreCase("-----BEGIN CERTIFICATE-----"))
		{
			boolean finish = false;
			pem += certificado + System.lineSeparator();
			while(!finish)
			{
				certificado = pIn.readLine();
				pem += certificado + System.lineSeparator();
				if(certificado.equalsIgnoreCase("-----END CERTIFICATE-----"))
				{
					finish = true;
				}
			}
		}
		return pem;
	}
	
	public boolean verificarCertificado(String pem)
	{
		try 
		{
			StringReader read = new StringReader(pem);
			PemReader pr = new PemReader(read);
			PemObject pemcertificado = pr.readPemObject();
			X509CertificateHolder certHolder = new X509CertificateHolder(pemcertificado.getContent());
			servidor = new JcaX509CertificateConverter().getCertificate(certHolder);
			pr.close();
			return true;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		return false;
	}

	public void cerrarConexiones()
	{
		try
		{
			in.close();
			out.close();
			socket.close();
		}
		catch (Exception e)
		{
			System.err.println("ERROR - ETAPA FINAL: Cierre de Conexiones");
		}
	}
	
	
	public void generarSeparador(){
	System.out.println("-----------------------------------------------------------------------");
	}

}