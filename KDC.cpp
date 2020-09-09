/**
RUN THIS ONE ON THING1
*/
#include <iostream>
#include <cerrno> 
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include "blowfish.cpp"
#include "blowfisha.cpp"
#include "blowfishb.cpp"


bool mode = true;

#define LENGTH  1500
using namespace std;
typedef unsigned char byte;
using namespace std;

void error(const char *msg){
	perror(msg);
	// exit(1);
}

/**
    checks to see if it is alpha numeric. 
*/
bool isValid(const string input){
    for(int i=0;input[i]!='\0';i++){
        if(!isalnum(input[i])){
            cout<<input[1]<<endl;
            return false; 
        }
    }
    return true;
}
/**
    checks to see if it is all numeric. 
*/
bool isNum(const std::string &input){
    return input.find_first_not_of("0123456789") == std::string::npos;
}


/**
    This function will prompt the user for a key to blowfish. 
    @variable the key you are looking for. 

*/
string keyPrompt(const string variable){
    char key [512];
    int length = 0;
    bool flag = true;
    string temp = "";
    
    while(flag){
        bzero(key, 512);
        cout<<"Please enter the key for "<<variable<<":"<<endl;
        scanf("%s",&key);
        temp = key;
        length = temp.length();
        //cout<<"lenght: "<<length<<endl;
        if(length % 8 == 0 && isValid(key)){
            flag = false;
        }
        else{
            cout<<"The "<<variable<<" you provided is not valid. Please try again."<<endl;
            //cout<<"current length: "<<length<<endl;
        }
    }
    //cout<<"this is the string: "<<key<<endl;
    return key;
}



/**
    This function will estabilish a connection to another thing. 
    @port this is the port you want to listen on . 
    @returns the connection number
*/
int connect(int port){
 //setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0){
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, 
        sizeof(servAddr));
    if(bindStatus < 0){
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    listen(serverSd, 5);
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    if(newSd < 0){
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    cout << "Awaiting client response..." << endl;//print to console 
    return newSd;
}

/**
    This oversized function will read the request nonce and then sent to Actor A the package with Eka[Ks||request||N1||Ekb[Ks||IDa]]
    @newSD the connection to Actor A
    @ka the blowfish key for A
    @kb the blowfish key for b
    @ks the session key for blowfish 
*/
 void requestResponse(int newSd,string ka, string kb, string ks ){
        string package = "";
        string temp = "";
        string aID = "10.35.195.46", nonce = "";
        char msg[1500];
        memset(&msg, 0, sizeof(msg));//clear the buffer
        char buffer[1500];
		bzero(buffer, 1500);
		int n = 0;
		n = read(newSd, buffer, 1500);//read the request nonce 
		if (n < 0){
             error("ERROR reading from socket");
        }
        cout<<"Requesting Ks for IDb.\n"<<"N1 recived: "<<buffer<<endl;//what do we make it equal
        BLOWFISHA bfa(ka);//creat As blowfish
        temp = ks;//set temp to ks
        temp = bfa.Encrypt_CBC(temp);//encrpt ks
        package = temp + "$";//add encrypt to package
        temp = buffer;//set temp to buffer (buffer is nonce) 
        nonce = buffer;// saving the nonce unencrypted
        temp = bfa.Encrypt_CBC(temp);//encrypt buffer
        package = package + temp + "$";//add buffer to package
        temp = "";//clear temp... just in case...
        BLOWFISHB bfb(kb);//creat Bs blowfish
        temp = bfb.Encrypt_CBC(ks);//encrypt ks with Bs key
        temp = bfa.Encrypt_CBC(temp);//now it it is ks encrypted with both B then A
        package = package + temp + "$";
        temp = bfb.Encrypt_CBC(aID);//encrypt aID and add it to temp (encrypted with B)
        temp = bfa.Encrypt_CBC(temp);//encrypt temp with As key (encrypted with B then A)
        package = package + temp + "$";//add temp to package
        temp = bfa.Decrypt_CBC(temp);
        temp = "";//clear out temp
        bzero(buffer,1500);
        strcpy(buffer, package.c_str());//turning the buffer to a string. 
        cout<<"Sendng to IDa:\n"<<buffer<<"\n\nKs: "<<ks<<"\nN1: "<<nonce<<endl;
        n = write(newSd, buffer, sizeof(buffer)+1);//sending the encripted Eka[Ks||request||N1||Ekb[Ks||IDa]]
        if (n < 0) {
		    printf("Error: key");
	    }
 }

//Server side
int main(int argc, char *argv[]){
	cout<<"Blowfish keys must only contain letters and numbers.  They must be a length divisible by 8.\n"<<endl;
	//BLOWFISH bf("FEDCBA9876543210");//I think this is the key?
    string ks = keyPrompt("Key for Ks");//"THISISAKEYBUDD69";
    string ka = keyPrompt("Key for Ka");//"FEUCBAK876T4HI2S";
    string kb = keyPrompt("Key for Kb");//"ABC123XYZ456GHYF";
    string aID = "10.35.195.46", nonce = "";
    int port = 9475;
    int newSd = connect(port);
    requestResponse(newSd,ka,kb,ks);
    close(newSd);
   
    return 0;   

}