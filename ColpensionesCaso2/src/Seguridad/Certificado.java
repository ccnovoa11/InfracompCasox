package Seguridad;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@SuppressWarnings("deprecation")
public class Certificado {

		private final static String algoritmo = "RSA";
		private KeyPair keys;


		public Certificado()
		{
			keys = null;
		}
		
		private  X509Certificate generarV3Certificate(KeyPair pair) throws Exception
		{
			PublicKey subPub = pair.getPublic();
			PrivateKey issPriv = pair.getPrivate();
			PublicKey issPub = pair.getPublic();

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
					new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), 
					new BigInteger(128, new SecureRandom()), 
					new Date(System.currentTimeMillis()), 
					new Date(System.currentTimeMillis() + 8640000000L), 
					new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), subPub);

			v3CertGen.addExtension(
					X509Extension.subjectKeyIdentifier, 
					false, 
					extUtils.createSubjectKeyIdentifier(subPub));

			v3CertGen.addExtension(
					X509Extension.authorityKeyIdentifier, 
					false, 
					extUtils.createAuthorityKeyIdentifier(issPub));

			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider("BC").build(issPriv)));
		}

		private KeyPair createKeyPair(String encryptionType, int byteCount) throws NoSuchProviderException, NoSuchAlgorithmException
		{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPairGenerator keysGenerator = KeyPairGenerator.getInstance(algoritmo, "BC");
			keysGenerator.initialize(1024);
			return keysGenerator.generateKeyPair();
		}

		private String convertCertificateToPEM(java.security.cert.X509Certificate cert) throws IOException 
		{
			StringWriter certificadoString = new StringWriter();
			JcaPEMWriter pemWriter = new JcaPEMWriter(certificadoString);
			pemWriter.writeObject(cert);
			pemWriter.close();
			return certificadoString.toString();
		}

		public String create(Date start, Date expiry, String encryptionType, int bitCount, String signatureAlgoritm) throws Exception
		{		
			KeyPair keyPair = createKeyPair(encryptionType, bitCount);
			keys = keyPair;
			return convertCertificateToPEM(generarV3Certificate(keys));
		}
		
		public KeyPair getKeys(){
			return keys;
		}
}
