# SEC
Project for the course of Project done on Highly Dependable Systems/Sistemas de Elevada Confiabilidade[SEC], the during the 2016/17 academic year.


## REPORT
https://www.overleaf.com/8400989mfbfjmbfkzcn

### Compile
cd to folder of the project (Client, CommonInterfaces or PasswordManager)

`mvn compile`

### Run
cd to folder of the project (Client or PasswordManager)
Made when runnin on local machine
#### Client
IPServer=localhost
ServerObjectName=password-manager
`mvn exec:java -Dexec.args="<IP-SERVER> <ServerObjectName> <port-1> <port-2> <port-3>"`

#### Server

`mvn exec:java -Dexec.args="<port-1> <port-2> <port-n>"`

###Install
cd to folder of the project (CommonInterfaces)

`mvn install`

