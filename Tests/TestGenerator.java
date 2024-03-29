import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class TestSlidesTable {

    public static void main(String args[]) throws IOException {

        String path = System.getProperty("user.dir") + File.separator;
        String outputFile = path + args[0];
        int port = 8006;
        String previous_ports = "";
        int rank = 1;
        File file = new File(outputFile);
        file.createNewFile();

        int number_of_servers = Integer.parseInt(args[1]);
        int number_of_bizantines = Integer.parseInt(args[2]);
        int number_of_clients = Integer.parseInt(args[3]);

        Files.write(Paths.get(outputFile), "cd ../PasswordManager\n".getBytes(),StandardOpenOption.APPEND);
        Files.write(Paths.get(outputFile), "call mvn clean compile\n".getBytes(),StandardOpenOption.APPEND);

        for(int i = 0; i< number_of_servers - number_of_bizantines; i++, port++) {
            Files.write(Paths.get(outputFile), ("start cmd /k mvn exec:java \"-Dexec.args=" + port + " 0\"\n").getBytes(), StandardOpenOption.APPEND);
            previous_ports += port + " ";
        }
        for(int i = 0; i< number_of_bizantines; i++, port++) {
            Files.write(Paths.get(outputFile), ("start cmd /k mvn exec:java \"-Dexec.args=" + port + " 3\"\n").getBytes(), StandardOpenOption.APPEND);
            previous_ports += port + " ";
        }
         Files.write(Paths.get(outputFile), "timeout /t 5\n".getBytes(), StandardOpenOption.APPEND);

        Files.write(Paths.get(outputFile), "cd ../Client\n".getBytes(), StandardOpenOption.APPEND);
        Files.write(Paths.get(outputFile), "call mvn clean compile\n".getBytes(),StandardOpenOption.APPEND);

        for(int i = 0; i< number_of_clients; i++, rank++) {
            Files.write(Paths.get(outputFile), ("start cmd /k mvn -Dtest=ClientIndependetTests#TestN -DargLine=\"-Dfaults="+number_of_bizantines+" -DnumberClients="+number_of_clients+ " -DnumberServers="+number_of_servers+"\" "+" test"+"\n").getBytes(), StandardOpenOption.APPEND);
        }
    }
}
