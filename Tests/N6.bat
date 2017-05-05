cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
start cmd /k mvn exec:java "-Dexec.args=8009 0"
start cmd /k mvn exec:java "-Dexec.args=8010 0"
start cmd /k mvn exec:java "-Dexec.args=8011 3"
timeout /t 5
cd ../Client
call mvn clean compile
start cmd /k mvn -Dtest=ClientIndependetTests#TestN -DargLine="-Dfaults=1 -DnumberClients=1 -DnumberServers=6"  test
