cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
start cmd /k mvn exec:java "-Dexec.args=8009 3"
cd ../Client
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=1 localhost password-manager 8006 8007 8008 8009 "
