All you need to do is, run the programs in this order:
1. DiffieHelmanGen.java
2. Alice.java
3. Bob.java


DIFFIEHELMANGEN.JAVA

DiffieHelmanGen will generate the p and g variables as well as the alphanumeric password used in Alice and Bob. 
Two files will be created. Parameters.txt and BobPw.txt.

Alice will be the only one to read from paramters.txt which contains p, g and hashed alphanum password.

BobPW.txt will contain the unhashed alphanum password. Bob program will read this alpha num and use it 
to match against the string keyed in by the user during program runtime. This is because new passwords
can be generated from Diffiehelmangen.java and i do not wish to hardcode a "default" password into Bob.java
to be used as comparator against the user's input. 

IF u wish to change the alphanumeric password used by Bob.java, delete parameters.txt and BobPW.txt and rerun
DiffieHelmanGenjava

Once done running Diffiehelmangen.java, just run Alice.java followed by Bob.java

In Bob.java, since the password is randomly generated and stored in BobPw.txt file, you can open the 
txt file to see the password required to log in.

OPEN SOURCE CODES USED IN PROGRAM DEVELOPMENT

Alice.java -> RC4 Class was sourced from github.
The Source is: https://github.com/engFathalla/RC4-Algorithm/blob/master/RC4/src/encryption/RC4.java

DiffieHelmanGen.java -> This entire program was also sourced from github. Only used certain files and not all of the 
ones found in the link. 
The Source is: https://github.com/bhepburn/CS789/tree/master/src/functions
