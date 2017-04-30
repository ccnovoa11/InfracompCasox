package Caso3;

import cliente.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task 
{

	@Override
	public void fail() 
	{
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() 
	{
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() 
	{
		try
		{
			Cliente cliente = new Cliente();
			System.out.println("Hola, soy un cliente");
			
		} 
		catch (Exception e) 
		{
			System.out.println("Error al crear cliente");
		}
	}

}