package util;

import javax.xml.bind.DatatypeConverter;

public class Hex {
	
	public static String transformarHEX( byte[] arregloB )
	{	
		return DatatypeConverter.printHexBinary(arregloB);
	}

	public static byte[] destransformarHEX( String ss )
	{	
		return DatatypeConverter.parseHexBinary(ss);
	}
	
	
	//SE AGREGA 
	public static byte[] decodificar( String ss)
	{
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public static String codificar( byte[] b )
	{
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
}
