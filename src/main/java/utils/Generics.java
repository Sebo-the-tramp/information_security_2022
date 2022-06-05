package utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Generics{

	public static String toHex(byte[] word) {
		
		StringBuilder sb = new StringBuilder();
		
		for (int i = 0; i < word.length; i++) {
	    	sb.append(Integer.toString((word[i] & 0xff) + 0x100, 16)
	                .substring(1));
	    }
		
		return sb.toString();
		
	}
	
	public static byte[] fromHex(String word) {
		
		byte[] binary = new byte[word.length()/2];
		for(int i = 0; i < binary.length; i++) {
			binary[i] = (byte) Integer.parseInt(word.substring(2*i, 2*i +2), 16);
		}
		return binary;
	}
	
	public static String readFromFile(String path) {
		
		String result = "";
		
		try {
		      File myObj = new File(path);
		      Scanner myReader = new Scanner(myObj);
		      while (myReader.hasNextLine()) {
		        String data = myReader.nextLine();
		        result += data;
		      }
		      myReader.close();
		    } catch (FileNotFoundException e) {
		      System.out.println("An error occurred.");
		      e.printStackTrace();
		    }
		
		return result;
	}
	
}