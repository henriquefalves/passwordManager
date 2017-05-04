package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidUsernameException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.WrongChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.*;

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
	private static boolean debug = true;
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
		byte[] receivedPassword;

		registerClient(client);

		byte[] domain = "facebook.com".getBytes(StandardCharsets.UTF_8);
		byte[] username = "henrique@hotmail.com".getBytes(StandardCharsets.UTF_8);
		byte[] password = "123456".getBytes(StandardCharsets.UTF_8);;

		client.save_password(domain, username, password);
		savePassword(client, "facebook.com", "henrique@hotmail.com", "123456");
		receivedPassword = retrievePassword(client, "facebook.com", "henrique@hotmail.com");
		System.out.println("(expected=123456) Result Get: " + new String(receivedPassword, StandardCharsets.UTF_8));

		/*byte[] password2 = "joaquim".getBytes(StandardCharsets.UTF_8);
		client.save_password(domain, username, password2);
		st = new String(client.retrieve_password(domain, username), StandardCharsets.UTF_8);
		System.out.println("PUT: "+"joaquim"+ " Result Get: " + st);*/

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
		boolean success;
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
					success = registerClient(client);
					if(success){
						System.out.println("You have registered successfully");
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
					success = savePassword(client, domain, username, password);
					if(success){
						System.out.println("Password Inserted/Updated Successfully");
					}
					break;

				case 3:
					System.out.println("Which Password you want to see?");
					System.out.println("Domain: ");
					String domainToSearch = reader.nextLine();
					System.out.println("Username: ");
					String usernameToSearch = reader.nextLine();
					System.out.println();
					byte[] response = retrievePassword(client, domainToSearch, usernameToSearch);
					if(response != null){
						System.out.println("Your password is " + new String(response, StandardCharsets.UTF_8)+ "\n");
					}
					break;

				case 4:
					client.close();
					logIn=false;
					System.out.println("You are now logged off");
					break;

				default:
					System.out.println("Error: No options with that command");
					break;
				}
			}
			catch(NumberFormatException e){
				System.out.println("Error: Insert a valid number");
			}
		}
		reader.close();
	}


	private static boolean registerClient(Client client){
		try {
			client.register_user();
			return true;
		} catch(DuplicatePublicKeyException d) {
			System.out.println("Error: You are already registered in the password manager");
			if(!presentationMode)
				d.printStackTrace();
		} catch(InvalidArgumentsException d) {
			System.out.println("Error: Invalid arguments");
			if(!presentationMode)
				d.printStackTrace();
		} catch(CorruptedMessageException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(MissingChallengeException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(InvalidChallengeException d) {
			System.out.println("Error: Your request was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(RemoteException r) {
			System.out.println("Error: There was an issue with the remote connection");
			if(!presentationMode)
				r.printStackTrace();
		} catch(Exception e) {
			System.out.println("Error: Unidentified error");
			if(!presentationMode)
				e.printStackTrace();
		}
		return false;
	}

	private static boolean savePassword(Client client, String domain, String username, String password){
		try {
			client.save_password(domain.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
			return true;
		} catch (InvalidDomainException id) {
			System.out.println("Error: Invalid Domain");
			if(!presentationMode)
				id.printStackTrace();
		} catch (InvalidUsernameException iu) {
			System.out.println("Error: Invalid Username");
			if(!presentationMode)
				iu.printStackTrace();
		} catch (InvalidPasswordException ip) {
			System.out.println("Error: Invalid Password");
			if(!presentationMode)
				ip.printStackTrace();
		} catch (InvalidArgumentsException ia) {
			System.out.println("Error: Invalid Domain and/or Username");
			if(!presentationMode)
				ia.printStackTrace();
		} catch(CorruptedMessageException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(MissingChallengeException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(InvalidChallengeException d) {
			System.out.println("Error: Your request was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(RemoteException r) {
			System.out.println("Error: There was an issue with the remote connection");
			if(!presentationMode)
				r.printStackTrace();
		} catch(Exception e) {
			System.out.println("Error: Unidentified error");
			if(!presentationMode)
				e.printStackTrace();
		}
		return false;
	}

	private static byte[] retrievePassword(Client client, String domain, String username){
		try {
			byte[] response = client.retrieve_password(domain.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8));
			return response;
		} catch (InvalidDomainException id) {
			System.out.println("Error: Invalid Domain");
			if(!presentationMode)
				id.printStackTrace();
		} catch (InvalidUsernameException iu) {
			System.out.println("Error: Invalid Username");
			if(!presentationMode)
				iu.printStackTrace();
		} catch (InvalidArgumentsException ia) {
			System.out.println("Error: Invalid Domain and/or Username");
			if(!presentationMode)
				ia.printStackTrace();
		} catch(CorruptedMessageException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(MissingChallengeException d) {
			System.out.println("Error: Your message was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch(InvalidChallengeException d) {
			System.out.println("Error: Your request was corrupted on network");
			if(!presentationMode)
				d.printStackTrace();
		} catch (WrongChallengeException d){
			System.out.println("Error: The server message was corrupted on network");
			if (!presentationMode)
				d.printStackTrace();
		} catch(RemoteException r) {
			System.out.println("Error: There was an issue with the remote connection");
			if (!presentationMode)
				r.printStackTrace();
		} catch(Exception e) {
			System.out.println("Error: Unidentified error");
			if(!presentationMode)
				e.printStackTrace();
		}
		return null;
	}



}

