# Blowfish_Assignment
Assignment to practice using encryption as well as exchanging data between two machines using.

Readme - Blowfish assignment

Authors: 
	Nikolo Sperberg, Sterling Rohlinger, Karin Knapp

Files:
	A.cpp 
	B.cpp
	KDC.cpp
	blowfish.cpp
	blowfisha.cpp
	blowfishb.cpp
Notes:
	A.cpp, B.cpp, and KDC.cpp must be complied with -std=c++11 to compile properly.
	File to be encrypted in A and sent over to B to be decrypted is currently hard coded into the code.
	KDC and B must be ran before A in order to work properly. 
	Encryption and decryption of the file can be toggled on and off by changing mode in A.ccp to true or false (true for with encryption).
	Encryption and decryption of the file can be toggled on and off by changing encryptOn in B.ccp to true or false (true for with encryption).
	
