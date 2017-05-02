package Caso3;

import cliente.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task 
{
	int i = 0;
	@Override
	public void fail() 
	{
	}

	@Override
	public void success() 
	{
	}

	@Override
	public void execute() 
	{
		try
		{
			Cliente cliente = new Cliente();
		} 
		catch (Exception e) 
		{
			System.out.println("Error al crear cliente "+e);
			i++;
			System.out.println(i);
		}
	}

}