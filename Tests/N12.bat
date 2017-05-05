cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
start cmd /k mvn exec:java "-Dexec.args=8009 0"
start cmd /k mvn exec:java "-Dexec.args=8010 0"
start cmd /k mvn exec:java "-Dexec.args=8011 0"
start cmd /k mvn exec:java "-Dexec.args=8012 0"
start cmd /k mvn exec:java "-Dexec.args=8013 0"
start cmd /k mvn exec:java "-Dexec.args=8014 0"
start cmd /k mvn exec:java "-Dexec.args=8015 3"
start cmd /k mvn exec:java "-Dexec.args=8016 3"
start cmd /k mvn exec:java "-Dexec.args=8017 3"
timeout /t 5
cd ../Client
call mvn clean compile
start cmd /k mvn -Dtest=ClientIndependetTests#TestN -DargLine="-Dfaults=3 -DnumberClients=1 -DnumberServers=12"  test
