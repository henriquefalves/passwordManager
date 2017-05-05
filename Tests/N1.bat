cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
timeout /t 5
cd ../Client
call mvn clean compile
start cmd /k mvn -Dtest=ClientIndependetTests#TestN -DargLine="-Dfaults=0 -DnumberClients=1 -DnumberServers=1"  test
