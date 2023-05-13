# Barking

Several methods to interact with kerberos.
The tool craft requests to kerberos and detect error types.
Currently it handles "principal unknown" and "pre-auth required".


go_build_Barking_.exe -dc 192.168.56.106 -account user2 -domain test -netbios client1
[:]\/\/\/\[:]
Principal Unknown

go_build_Barking_.exe -dc 192.168.56.106 -account user -domain test -netbios client1
[:]\/\/\/\[:]
Pre-Auth required

