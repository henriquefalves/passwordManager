cd CommonInterfaces
start cmd /k mvn clean install
cd ../PasswordManager
start cmd /k mvn clean compile exec:java
cd ../Client
start cmd /k mvn clean compile exec:java
