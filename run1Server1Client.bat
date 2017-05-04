cd CommonInterfaces
start cmd /k mvn clean install
cd ../PasswordManager
REM Normal Server
start cmd /k mvn clean compile exec:java "-Dexec.args=8007 0"
cd ../Client
start cmd /k mvn clean compile exec:java "-Dexec.args=1 localhost password-manager 8007"
