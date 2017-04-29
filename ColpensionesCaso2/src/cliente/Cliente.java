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

public class Cliente {

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
	private final static String IP = "localhost";
	private final static int PUERTO = 4443;
	private static Socket socket;

	// Variables de consola
	private static PrintWriter out;
	private static BufferedReader in;
	
	//Variables de seguridad
	private static Certificado certificado;
	private static X509Certificate servidor;
	private static KeyPair keys;
	private static PublicKey llavePublicaServidor;
	private static SecretKey llaveSimetrica;
	private static CifradoAsimetrico cifradoAsimetrico;
	private static CifradoSimetrico cifradoSimetrico;
	private static HMAC hmac;
	private static Hex converter;
	
	public static void inicializar(){
		System.out.println("Incializando las variables");
		certificado = new Certificado();
		cifradoSimetrico = new CifradoSimetrico();
		cifradoAsimetrico = new CifradoAsimetrico();
		hmac = new HMAC();
		converter = new Hex();
		try 
		{	
			System.out.println("Creando el Socket con la direccion: " + IP + " y el puerto: " + PUERTO);

			System.out.println("prueba0.1");
			socket = new Socket(IP, PUERTO);
			out = new PrintWriter(socket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader( socket.getInputStream()));
		}
		catch (Exception e) 
		{
			System.err.println("Error en la inicializacion de variables"); 
		}
	}
	
	public static void main(String[] args) throws IOException{
		generarSeparador();
		inicializar();
		generarSeparador();
		iniciarComunicacion();
		generarSeparador();
		intercambioCD();
		generarSeparador();
		autenticacion();
		generarSeparador();
		consulta();
		cerrarConexiones();
	}
	
	public static void iniciarComunicacion(){
		try{
			System.out.println("ETAPA 1: INICIO DE SESIÓN");
			out.println(HOLA);
			System.out.println(HOLA);
			String rta = in.readLine();
			System.out.println(rta);

			if (rta.equals(OK))
			{
				System.out.println("Se confirma la comunicacion entre cliente y servidor");
				System.out.println("Enviando Algoritmo");
				System.out.println(ALGORITMOS);
				out.println(ALGORITMOS);
			}
		}
		catch (Exception e)
		{
			System.err.println("ERROR - ETAPA1: inicio de sesion");
		}
	}
	
	public static void intercambioCD() throws IOException{
		String respuesta = in.readLine();
		if(respuesta.equals(OK)){
			try{
				System.out.println("ETAPA 2: INTERCAMBIO DE CD");
				String ct = certificado.create(new Date(), new Date(), "RSA", 512, "SHA1withRSA");
				keys = certificado.getKeys();
				out.println(ct);
				System.out.println("CERTIFICADO CLIENTE: "+ ct);
				String pem = leerCertificado(in);
				verificarCertificado(pem);
				llavePublicaServidor = servidor.getPublicKey();
				System.out.println("CERTIFICADO SERVIDOR: " + pem);
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
	
	public static void autenticacion() throws IOException{
		System.out.println("ETAPA 3: AUTENTICACIÓN");
		
		//----------------RETO 1----------------------------------------------------------------
		System.out.println("RETO 1:");
		//Cifrado reto 1
		int numReto = (int) (Math.random()*100);
		String reto1 = Integer.toString(numReto);
		System.out.println("número del reto 1: " + reto1);
		byte[] cifradoReto1 = cifradoAsimetrico.cifrar(reto1, llavePublicaServidor);
		String reto1Enviar = converter.transformarHEX(cifradoReto1);
		out.println(reto1Enviar);
		
		//Descifrado reto 1
		in.readLine(); //vacío
		String reto1server = in.readLine();
		byte[] sreto1 = converter.destransformarHEX(reto1server);
		byte[] descifradoReto1 = cifradoAsimetrico.descifrar(sreto1, keys);
		String servidornum = new String(descifradoReto1);
		if(reto1.equals(servidornum)){
			out.println(OK);
			System.out.println("RETO 1 PASADO");
		}else{
			out.println(ERROR);
			System.out.println("RETO 1 NO PASADO");
		}
		
		//---------------RETO 2--------------------------------------------------------------------
		System.out.println("RETO 2:");
		//Descifrado reto 2
		String reto2 = in.readLine();
		byte[] byreto2 = converter.destransformarHEX(reto2);
		byte[] descifradoReto2 = cifradoAsimetrico.descifrar(byreto2, keys);
		String streto2 = new String(descifradoReto2);
		System.out.println("número descifrado reto 2: "+ streto2);
		//cifrado reto 2
		byte[] cifrarReto2 = cifradoAsimetrico.cifrar(streto2, llavePublicaServidor);
		String reto2cifrado = converter.transformarHEX(cifrarReto2);
		out.println(reto2cifrado);
		System.out.println("RETO 2 TERMINADO");
	}
	
	public static void consulta() throws IOException{
		System.out.println("ETAPA 4: CONSULTA");
		
		//LLAVE SIMÉTRICA
		String llavesim = in.readLine();
		byte[] desllavesim = converter.destransformarHEX(llavesim);
		byte[] simkey = cifradoAsimetrico.descifrar(desllavesim, keys);
		SecretKeySpec sk = new SecretKeySpec(simkey, ALGS);
		llaveSimetrica = sk;
		System.out.println("Llave simétrica: " + llaveSimetrica);
		
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
		System.out.println("Mensaje enviado: " + mensaje);
		
		//Descifrar respuesta
		String[] rta = in.readLine().split(SEPARADOR);
		byte[] ccrta = converter.destransformarHEX(rta[0]);
		byte[] hashrta = converter.destransformarHEX(rta[1]);
		String desccrta = cifradoSimetrico.descifrar(ccrta, llaveSimetrica);
		String deshashrta = cifradoSimetrico.descifrar(hashrta, llaveSimetrica);
		
		if(desccrta.equals("Este mensaje es la respuesta a su consulta")){
			System.out.println(desccrta);
			System.out.println("COMUNICACIÓN EXITOSA, FIN DEL PROTOCOLO");
			out.println(OK);
		}
	}
	
	public static String leerCertificado(BufferedReader pIn) throws IOException{
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
	
	public static boolean verificarCertificado(String pem)
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

	public static void cerrarConexiones()
	{
		try
		{
			System.out.println("Cerrando las conexiones establecidas");
			in.close();
			out.close();
			socket.close();
		}
		catch (Exception e)
		{
			System.err.println("ERROR - ETAPA FINAL: Cierre de Conexiones");
		}
	}
	
	
	public static void generarSeparador(){
	System.out.println("-----------------------------------------------------------------------");
	}

}