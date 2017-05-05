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
`mvn exec:java -Dexec.args="<UserRank> <IP-SERVER> <ServerObjectName> <NrFaults> <port-1-Server> <port-2-Server> <port-n-Server>"`

#### Server

Type-Of-Byzantine-Behaviour 
0 - Normal
1 - Crash
2 - Timeout responses
3 - Corruped Data(password)

`mvn exec:java -Dexec.args="<port> <Type-Of-Byzantine-Behaviour>"`

###Install
cd to folder of the project (CommonInterfaces)

`mvn install`

