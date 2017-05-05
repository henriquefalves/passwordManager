cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
start cmd /k mvn exec:java "-Dexec.args=8009 0"
start cmd /k mvn exec:java "-Dexec.args=8010 0"
start cmd /k mvn exec:java "-Dexec.args=8011 0"
start cmd /k mvn exec:java "-Dexec.args=8012 3"
start cmd /k mvn exec:java "-Dexec.args=8013 3"
timeout /t 5
cd ../Client
call mvn clean compile
start cmd /k mvn -Dtest=ClientIndependetTests#TestN -DargLine="-Dfaults=2 -DnumberClients=1 -DnumberServers=8"  test
