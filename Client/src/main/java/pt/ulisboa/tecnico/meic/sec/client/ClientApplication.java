package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InexistentTupleException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;
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
import java.util.Scanner;

public class ClientApplication {

	/**
	 * Defines user interaction or automatic
	 */
	private static boolean debug = true;
	/**
	 * Defines if the program should printStackTrace of Execeptions
	 */
	private static boolean presentationmode = false;
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
			System.out.println(e.getMessage());
			if(!presentationmode)
				e.printStackTrace();
		} catch (NotBoundException e) {
			System.out.println(e.getMessage());
			if(!presentationmode)
				e.printStackTrace();
		} catch (MalformedURLException e) {
			System.out.println(e.getMessage());
			if(!presentationmode)
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

		while(true) {
            try {
                System.out.println("Please provide the file name of the Keystore:");
                String keystoreFileName = reader.nextLine();
                System.out.println("Password to access Keystore:");
                String keystorePassword = reader.nextLine();

                keystoreFileName += ".jks";
                client.init(ks, keystoreFileName, keystorePassword);
                break;

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
						System.out.println("You have been registered");
					} catch(RemoteException r) {
						System.out.println("There was an issue with the remote connection");
						if(!presentationmode)
							r.printStackTrace();
					} catch(DuplicatePublicKeyException d) {
						System.out.println("You are already registered in the password manager");
						if(!presentationmode)
							d.printStackTrace();
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationmode)
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
						if(!presentationmode)
							r.printStackTrace();
					} catch (InvalidDomainException id) {
						System.out.print("Invalid Domain");
						if(!presentationmode)
							id.printStackTrace();
					} catch (InvalidUsernameException iu) {
						System.out.print("Invalid Username");
						if(!presentationmode)
							iu.printStackTrace();
					} catch (InvalidPasswordException ip) {
						System.out.print("Invalid Password");
						if(!presentationmode)
							ip.printStackTrace();
					} catch (InvalidArgumentsException ia) {
						System.out.print("Invalid Password and/or Username");
						if(!presentationmode)
							ia.printStackTrace();
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationmode)
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
						if (!presentationmode)
							r.printStackTrace();
					} catch (InvalidDomainException id) {
						System.out.print("Invalid Domain");
						if(!presentationmode)
							id.printStackTrace();
					} catch (InvalidUsernameException iu) {
						System.out.print("Invalid Username");
						if(!presentationmode)
							iu.printStackTrace();
					} catch (InexistentTupleException it) {
						System.out.println("Incorrect username/domain.");
					} catch(Exception e) {
						System.out.println("Unidentified error");
						if(!presentationmode)
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

