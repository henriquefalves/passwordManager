package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;


public class ServerApplication {

    public static void main(String[] args) {

        int registryPort = 8006;
        try {
            Server passwordManager = new Server();
            System.out.println("Server created");
            Registry reg = LocateRegistry.createRegistry(registryPort);
            System.out.println("Registry created!!");
            reg.rebind("password-manager", passwordManager);
            System.out.println("Rebind done!!");

            System.out.println("Press Enter to exit");
            String button = (new Scanner(System.in)).nextLine();

        } catch (AccessException e) {
            e.printStackTrace();
        } catch (RemoteException e) {
            e.printStackTrace();
        }

    }
}
