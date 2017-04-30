/**
 * 
 */
package Caso3;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	
	public Generator() 
	{
		Task work = createTask();
		// Numero de Tareas
		int numberofTasks = 100;
		// Cada cuanto se hacen
		int gapBetweenTasks = 1000;
		generator = new LoadGenerator("carga clientes", numberofTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	private Task createTask()
	{
		return new ClientServerTask();
	}
	
	public static void main(String[] args) 
	{
		Generator gen = new Generator();
	}
}