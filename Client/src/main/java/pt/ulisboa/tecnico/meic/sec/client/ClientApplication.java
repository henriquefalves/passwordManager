package pt.ulisboa.tecnico.meic.sec.client;


import java.rmi.RemoteException;

public class ClientApplication {
    public static void main(String[] args) {
        System.out.println("SUCCESS CLIENT");
        try {
            Client c = new Client();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }
}
