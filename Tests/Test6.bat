cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
timeout /t 5
cd ../Client
call mvn clean compile
start cmd /k mvn -Dtest=ClientIndependetTests#Test6 -DargLine="-Dfaults=0 -DnumberClients=3 -DnumberServers=3"  test
