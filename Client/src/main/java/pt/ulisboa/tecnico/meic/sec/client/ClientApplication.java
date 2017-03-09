package pt.ulisboa.tecnico.meic.sec.client;


import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Scanner;
import java.security.*;
import java.security.cert.CertificateException;


public class ClientApplication {

	static public KeyStore getKeyStore(String keyStoreName, char[] passwordKeyStore){
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		FileInputStream fis=null;

		try {
			fis = new FileInputStream(keyStoreName);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			ks.load(fis, passwordKeyStore);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally{
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return ks;

	}

	public static void main(String[] args) {

		try {
			ServerAPI server = (ServerAPI) Naming.lookup("rmi://localhost:8006/password-manager");
			Client client = new Client(server);

			client.init(getKeyStore("henriqueKeyStore.jks", "henrique123".toCharArray()));


			byte[] domain = "domain".getBytes(StandardCharsets.UTF_8);
			byte[] username = "username".getBytes(StandardCharsets.UTF_8);
			byte[] password = "password".getBytes(StandardCharsets.UTF_8);
			client.register_user();
			client.save_password(domain, username, password);
			String st = new String(client.retrieve_password(domain, username));
			System.out.println("Result of get: " + st);


			System.out.println("Press Enter to exit");
			String button = (new Scanner(System.in)).nextLine();
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (NotBoundException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}

	}

}

