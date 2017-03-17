package pt.ulisboa.tecnico.meic.sec.client;


import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Scanner;


public class ClientApplication {

	private static boolean debug = false;
	public static void main(String[] args) {

		try {
			String name = "rmi://"+args[0]+":"+args[1]+"/"+args[2];
			Client client = new Client(name);
			
			KeyStore ks = null;
			try {
				ks = KeyStore.getInstance("JCEKS");
			} catch (KeyStoreException e) {
				System.out.println("Unable to create Keystore");
			}
			if(!debug)
				automated(client, ks);
			else
				userInteraction(client,ks);
				
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (NotBoundException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

	private static void automated(Client client, KeyStore ks) {
		String keystoreName = "henriqueKeyStore.jks";
		String keystorePassword = "henrique123";
		client.init(ks, keystoreName, keystorePassword);

		client.register_user();

		byte[] domain = "facebook.com".getBytes(StandardCharsets.UTF_8);
		byte[] username = "henrique@hotmail.com".getBytes(StandardCharsets.UTF_8);
		byte[] password = "123456".getBytes(StandardCharsets.UTF_8);
		System.out.println("Will Put pass: 123456");
		client.save_password(domain, username, password);
		String st = new String(client.retrieve_password(domain, username), StandardCharsets.UTF_8);
		System.out.println("Result of First Get: " + st);
		
		
		domain = "twitter.com".getBytes(StandardCharsets.UTF_8);
		username = "henrique@hotmail.com".getBytes(StandardCharsets.UTF_8);
		password = "654321".getBytes(StandardCharsets.UTF_8);
		System.out.println("Will Put pass: 654321");

		client.save_password(domain, username, password);
		
		 st = new String(client.retrieve_password(domain, username), StandardCharsets.UTF_8);
		System.out.println("Result of Second Get: " + st);


		System.out.println("Press Enter to exit");
		String button = (new Scanner(System.in)).nextLine();
	}

	private static void userInteraction(Client client, KeyStore ks){
		Scanner reader = new Scanner(System.in);
		boolean logIn=true;
		System.out.println("####### WELCOMME  to Dependable Password Manager #######");
		System.out.println("Please provide the file name of the Keystore:");
		String keystoreFileName = reader.nextLine();
		System.out.println("Password to access Keystore:");
		String keystorePassword = reader.nextLine();
		
		client.init(ks, keystoreFileName, keystorePassword);

		String domain;
		while(logIn){
			System.out.println(""
					+ "1 - Save Password\n"
					+ "2 - Retrive Password\n"
					+ "3 - Log Out\n");
			String choice = reader.nextLine();

			switch (Integer.parseInt(choice)) {
			case 1:
				System.out.println("To save the password please complete the following:");
				System.out.println("Domain: ");
				domain = reader.nextLine();
				System.out.println("Username: ");
				String username = reader.nextLine();
				System.out.println("Password: ");
				String password = reader.nextLine();
				System.out.println();
				client.save_password(domain.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
				System.out.println("Password Inserted/Updated Successfully");
				
				break;
			case 2:
				System.out.println("Which Password you want to see?");
				System.out.println("Domain: ");
				String domainToSearch = reader.nextLine();
				System.out.println("Username: ");
				String usernameToSearch = reader.nextLine();
				System.out.println();
				client.retrieve_password(domainToSearch.getBytes(StandardCharsets.UTF_8), usernameToSearch.getBytes(StandardCharsets.UTF_8));
				break;
				
			case 3:
				client.close();
				logIn=false;
				break;
			default:
				System.out.println("No options with that command");
				break;
			}
		}

		reader.close();
	}

}

