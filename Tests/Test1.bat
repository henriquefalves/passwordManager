cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
cd ../Client
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=1 localhost password-manager 8006 "
