# SEC
Project for the course of Project done on Highly Dependable Systems/Sistemas de Elevada Confiabilidade[SEC], the during the 2016/17 academic year.


## REPORT
https://www.overleaf.com/8400989mfbfjmbfkzcn

### Compile
cd to folder of the project (Client, CommonInterfaces or PasswordManager)

`mvn compile`

### Run
cd to folder of the project (Client or PasswordManager)

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

### Install
cd to folder of the project (CommonInterfaces)

`mvn install`

### TESTS
Batch scripts located on the Tests folder
<br />
From N1 to N13 follow set up of slide 52 from the pdf https://fenix.tecnico.ulisboa.pt/downloadFile/1407993358852871/sec-1617-05-distributed-system-model.pdf. All are tested with a single client doing a write and read.
<br />

Tests implement can be seen on the following link
 https://docs.google.com/spreadsheets/d/1S62-LEjgt0qOoKVpU0hMaLflEOnsudiUdsZhhKHrT2g/edit#gid=1499719979
