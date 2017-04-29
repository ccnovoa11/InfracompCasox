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
}
