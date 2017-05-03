package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidUsernameException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Scanner;

public class ClientApplication {

	/**
	 * Defines user interaction or automatic
	 */
	private static boolean debug = false;
	/**
	 * Defines if the program should printStackTrace of Execeptions
	 */
	public static boolean presentationMode = true;
	public static void main(String[] args) {

		try {
			ArrayList<String> serverNames = new ArrayList<>();
			String rank = args[0];
			String address = args[1];
			String objectName = args[2];
			for(int i = 3; i < args.length; i++) {
				serverNames.add("rmi://"+address+":"+args[i]+"/"+objectName);
			}
			Client client = new Client(rank, serverNames);

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
			System.out.println(e.getMessage());
			if(!presentationMode)
				e.printStackTrace();
		} catch (NotBoundException e) {
			System.out.println(e.getMessage());
			if(!presentationMode)
				e.printStackTrace();
		} catch (MalformedURLException e) {
			System.out.println(e.getMessage());
			if(!presentationMode)
				e.printStackTrace();
		}
	}

	private static void automated(Client client, KeyStore ks) throws RemoteException {
		String keystoreName = "henriqueKeyStore.jks";
		String keystorePassword = "henrique123";

        try {
            client.init(ks, keystoreName, keystorePassword);
        } catch (UnrecoverableKeyException uke) {
            System.out.println("Unable get KeyPair");
        } catch (KeyStoreException kse) {
            System.out.println("Unable get KeyPair");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Unable get KeyPair");
        } catch (CertificateException e) {
            System.out.println("Unable get KeyPair");
        } catch (IOException e) {
            System.out.println("Unable get KeyPair");
        }

        client.register_user();

		byte[] domain = "facebook.com".getBytes(StandardCharsets.UTF_8);
		byte[] username = "henrique@hotmail.com".getBytes(StandardCharsets.UTF_8);
		String passwordString = "123456";
		byte[] password = passwordString.getBytes(StandardCharsets.UTF_8);
		client.save_password(domain, username, password);

		String st = new String(client.retrieve_password(domain, username), StandardCharsets.UTF_8);
		System.out.println("PUT: "+"123456"+ " Result Get: " + st);

		byte[]domain2 = "twitter.com".getBytes(StandardCharsets.UTF_8);
		byte[]username2 = "henrique@hotmail.com".getBytes(StandardCharsets.UTF_8);
		String passwordString2 = "654321";
		byte[]password2 = passwordString2.getBytes(StandardCharsets.UTF_8);
		client.save_password(domain2, username2, password2);
		st = new String(client.retrieve_password(domain2, username2), StandardCharsets.UTF_8);
		System.out.println("PUT: "+passwordString2+ " Result Get: " + st);

		System.out.println("Press Enter to exit");
		String button = (new Scanner(System.in)).nextLine();
	}

	private static void userInteraction(Client client, KeyStore ks){
		Scanner reader = new Scanner(System.in);
		boolean logIn=true;
		System.out.println("####### WELCOMME  to Dependable Password Manager #######");

		while(true) {
            try {
                System.out.println("Please provide the file name of the Keystore:");
                String keystoreFileName = reader.nextLine();
                System.out.println("Password to access Keystore:");
                String keystorePassword = reader.nextLine();

                keystoreFileName += ".jks";
                client.init(ks, keystoreFileName, keystorePassword);
                System.out.println("KeyPair obtained");
                break;

            } catch (UnrecoverableKeyException uke) {
                System.out.println("Unable get KeyPair");
				if(!presentationMode)
					uke.printStackTrace();
			} catch (KeyStoreException kse) {
                System.out.println("Unable get KeyPair");
				if(!presentationMode)
					kse.printStackTrace();
			} catch (NoSuchAlgorithmException nsae) {
                System.out.println("Unable get KeyPair");
				if(!presentationMode)
					nsae.printStackTrace();
			} catch (CertificateException ce) {
                System.out.println("Unable get KeyPair");
				if(!presentationMode)
					ce.printStackTrace();
			} catch (IOException e) {
                System.out.println("Unable get KeyPair");
				if(!presentationMode)
					e.printStackTrace();
			}
        }

		String domain;
		while(logIn){
			System.out.println(""
					+ "1 - Register\n"
					+ "2 - Save Password\n"
					+ "3 - Retrive Password\n"
					+ "4 - Log Out\n");
			String choice = reader.nextLine();

			try{
				int parseInt = Integer.parseInt(choice);

				switch (parseInt) {
				case 1:
					try {
						client.register_user();
					} catch(RemoteException r) {
						System.out.println("There was an issue with the remote connection");
						if(!presentationMode)
							r.printStackTrace();
					} catch(DuplicatePublicKeyException d) {
						System.out.println("You are already registered in the password manager");
						if(!presentationMode)
							d.printStackTrace();
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationMode)
							e.printStackTrace();
					}
					break;

				case 2:
					System.out.println("To save the password please complete the following:");
					System.out.println("Domain: ");
					domain = reader.nextLine();
					System.out.println("Username: ");
					String username = reader.nextLine();
					System.out.println("Password: ");
					String password = reader.nextLine();
					System.out.println();
					try {
						client.save_password(domain.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
						System.out.println("Password Inserted/Updated Successfully");
					} catch(RemoteException r) {
						System.out.println("There was an issue with the remote connection");
						if(!presentationMode)
							r.printStackTrace();
					} catch (InvalidDomainException id) {
						System.out.print("Invalid Domain");
						if(!presentationMode)
							id.printStackTrace();
					} catch (InvalidUsernameException iu) {
						System.out.print("Invalid Username");
						if(!presentationMode)
							iu.printStackTrace();
					} catch (InvalidPasswordException ip) {
						System.out.print("Invalid Password");
						if(!presentationMode)
							ip.printStackTrace();
					} catch (InvalidArgumentsException ia) {
						System.out.print("Invalid Password and/or Username");
						if(!presentationMode)
							ia.printStackTrace();
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationMode)
							e.printStackTrace();
					}
					break;

				case 3:
					System.out.println("Which Password you want to see?");
					System.out.println("Domain: ");
					String domainToSearch = reader.nextLine();
					System.out.println("Username: ");
					String usernameToSearch = reader.nextLine();
					System.out.println();
					try {
						byte[] response = client.retrieve_password(domainToSearch.getBytes(StandardCharsets.UTF_8), usernameToSearch.getBytes(StandardCharsets.UTF_8));
						System.out.println("Your password is " + new String(response, StandardCharsets.UTF_8)+ "\n");
					} catch(RemoteException r) {
						System.out.println("There was an issue with the remote connection");
						if (!presentationMode)
							r.printStackTrace();
					} catch (InvalidDomainException id) {
						System.out.print("Invalid Domain");
						if(!presentationMode)
							id.printStackTrace();
					} catch (InvalidUsernameException iu) {
						System.out.print("Invalid Username");
						if(!presentationMode)
							iu.printStackTrace();
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationMode)
							e.printStackTrace();
					}
					break;

				case 4:
					client.close();
					logIn=false;
					System.out.println("You are now logged off");
					break;

				default:
					System.out.println("No options with that command");
					break;
				}
			}
			catch(NumberFormatException e){
				System.out.println("Insert a valid number");
			}
		}
		reader.close();
	}
}

