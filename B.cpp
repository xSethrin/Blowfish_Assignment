/**
    runs on thing3
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
#include "blowfishb.cpp"
bool encryptOn = true;
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
    This will prompt the user for a nonce. 
*/
long noncePrompt(const string variable){
    long nonce = 0;
    char snonce [255];
    int length = 0;
    bool flag = true;
    string temp = "";
    
    while(flag){
        bzero(snonce, 19);
        cout<<"Please enter the key for "<<variable<<":"<<endl;
        scanf("%s",&snonce);
        temp = snonce;
        length = temp.length();
        if(length <= 16 && isNum(snonce)){
            nonce = std::stol(snonce, 0);
            if(nonce > 0 ){
                flag = false;
            }
            else{
                cout<<"The "<<variable<<" you provided is not valid. Please try again."<<endl;
            }        
        }
        else{
            cout<<"The "<<variable<<" you provided is not valid. Please try again."<<endl;
        }
    }
    return nonce;
}

/*
function to change nonce
*/
long f(long nonce) {
    const long A = 48271;
    const long M = 2147483647;
    const long Q = M/A;
    const long R = M%A;

	static long state = 1;
	long t = A * (state % Q) - R * (state / Q);
	
	if (t > 0)
		state = t;
	else
		state = t + M;
	return (long)(((double) state/M)* nonce);
}

long randomNonce(){
    long nonce = 1;
    int x = 0;
    for(int i = 0; i <= 5; i++){
        x = rand();
        nonce = (nonce + nonce) * x;
    }
    return nonce;
}

/*
function to set up connection to client
*/
int connect(int port){
//setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
 
    //open stream oriented socket with internet address
    //also keep track of the socket descriptor
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0){
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    //bind the socket to its local address
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, 
        sizeof(servAddr));
    if(bindStatus < 0){
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    //listen for up to 5 requests at a time
    listen(serverSd, 5);
    //receive a request from client using accept
    //we need a new address to connect with the client
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    //accept, create a new socket descriptor to 
    //handle the new connection with client
    int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    if(newSd < 0){
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    return newSd;
}


/*
returns ks
*/
string getKs(BLOWFISHB bfb, int newSd){
    /* make needed local variables */
    string aID = "", ks = "", temp = "";
    int n = 0, i = 0, count = 0;
    char buffer[LENGTH];

    bzero(buffer, LENGTH);//zero out buffer 
    cout << "Awaiting client response..." << endl;//print to console
    //memset(&msg, 0, sizeof(msg));//clear the buffer  
    bzero(buffer, LENGTH);//zero out buffer
    n = read(newSd, buffer, sizeof(buffer));//read package from client
    if (n < 0) error("ERROR reading from socket");//check for error
    cout<<"Recieved encrypted file:\n"<<buffer<<endl;//print recived package
  
    while(i < LENGTH){//search for $
        if(buffer[i] == '$'){
            if(count == 0){//found ebcrypted ks
                ks = temp;//set temp to ks
                temp.clear();//clear temp
            }
            if(count == 1){//found encrypted aID
                aID = temp;//set aID to temp
            }
            count++;
        }else{
            temp = temp + buffer[i];//add char to temp
        }
        i++;
    }
    //cout<<"Encrypted aid: \n"<<aID<<endl;
    //cout<<"Encrypted Ks: \n"<<ks<<endl;
    ks = bfb.Decrypt_CBC(ks);//decrypt ks
    aID = bfb.Decrypt_CBC(aID);//decrypt aID
    cout<<"Received IDa: \n"<<aID<<endl;
    cout<<"Recevied Ks: \n"<<ks<<endl;
    return ks;
}

/*
function to handle nonce returns true if nonces are the same, false if not
*/
bool nonceMaster(long nonce, BLOWFISH bfs, int newSd){
    /* make global variables */
    char buffer[LENGTH];
    int n = 0;
    string snonce = "", checkNonce = "";

    bzero(buffer, LENGTH);//zero out buffer
    cout<<"N2: "<<nonce<<endl;//print to console
    snonce = to_string(nonce);//convert nonce to string
    snonce = bfs.Encrypt_CBC(snonce);//encrypt nonce with ks
    cout<<"Encrypted N2: "<<snonce<<endl;
    bzero(buffer, LENGTH);//zero out buffer
    strcpy(buffer, snonce.c_str());//forcefully shove snonce into buffeer
    n = write(newSd, buffer, LENGTH);//sending nonce to a.
    if (n < 0) error("ERROR writting from socket");//reports an erro?
    nonce = f(nonce);//use function on nonce to makesure it is the same as the one A will send back
    snonce = to_string(nonce);//convert nonce to string
    n = read(newSd, buffer, sizeof(buffer));//read in nonce from A
    if (n < 0) error("ERROR reading from socket");//error report
    checkNonce = buffer;//set checkNonce to buffer for decryption
    checkNonce = bfs.Decrypt_CBC(checkNonce);//decrypt checknonce
    cout<<"Decrypted f(N2) from IDa: "<<checkNonce<<endl;
    if(snonce.compare(checkNonce) != 0 ){//check if nonce the same 
        cout << "nonce check failed\n";
        return false;//return false if nonces are different
    }
    cout<<"Both f(N2)s match."<<endl;
    return true;//return true in nonces are the same
}

/*
function that tells client server is ready to receive file 
*/
void ready(BLOWFISH bfs, int newSd){
    /* create local variables*/
    char buffer[LENGTH];
    string ready = "ready";
    int n = 0;

    bzero(buffer, LENGTH);//zero out buffer
    ready = bfs.Encrypt_CBC(ready);
    bzero(buffer, LENGTH);
    strcpy(buffer, ready.c_str());
    n = write(newSd, buffer, LENGTH);
    if (n < 0) error("ERROR writting from socket");//reports an erro?

}

/*
function that receives file
this one is without encryption
*/
void receiveFile(BLOWFISH bfs, int newSd, FILE *fr){
    string temp = "";
    char revbuf[LENGTH];
    int fr_block_sz = 0;

    bzero(revbuf, LENGTH);
    while (((fr_block_sz = recv(newSd, revbuf, LENGTH, 0)) > 0)){//if we are not encrypting
        int write_sz = fwrite(revbuf, sizeof(char), fr_block_sz, fr);
        if (write_sz < fr_block_sz){
            error("File write failed on server.\n");
        }
        //bzero(array, temp_length);
        if (fr_block_sz == 0 || fr_block_sz != 512){
            //break;
        }
        bzero(revbuf, LENGTH);
    }
    if (fr_block_sz < 0){
        if (errno == EAGAIN){
            printf("recv() timed out.\n");
        }else{
            fprintf(stderr, "recv() failed due to errno = %d\n", errno);
            exit(1);
        }
    }
    printf("Ok received from client!\n");

}

/*
function to recieve encrypted file from client
*/
void receiveEncryptedFile(BLOWFISH bfs, int newSd, FILE *fr){
    string temp = "";
    char revbuf[LENGTH];
    int fr_block_sz = 0;
    bzero(revbuf, LENGTH);
    while (((fr_block_sz = recv(newSd, revbuf, LENGTH, 0)) > 0)){//if we want to encrypt
        //cout<<"Begining decrypting"<<endl;
        int i = 0;
        while(i < LENGTH){
            if(revbuf[i] == '$'){
               // cout<<"temp before decryption :"<<temp<<endl;
                temp = bfs.Decrypt_CBC(temp);
                char array[temp.length()+1];
                strcpy(array, temp.c_str());
                //cout<<"this is the file: "<<array<<endl;
                int write_sz = fwrite(array, sizeof(char), temp.length()+1, fr);
                bzero(array, temp.length());
                temp.clear();
                
            }else{
                temp = temp + revbuf[i];
            }
            i++;
        }
        i = 0;
        bzero(revbuf, LENGTH);      
    }
    if (fr_block_sz < 0){
        if (errno == EAGAIN){
            printf("recv() timed out.\n");
        }else{
            fprintf(stderr, "recv() failed due to errno = %d\n", errno);
            exit(1);
        }
    }
}


/**
driver function 
*/
int main(int argc, char *argv[]){
	cout<<"Blowfish keys must only contain letters and numbers.  They must be a length divisible by 8.\nNonce must be at most 16 digits long."<<endl;
    string keyb=keyPrompt("Key b");
    BLOWFISHB bfb(keyb);//I think this is the key?
    long nonce = noncePrompt("nonce");//randomNonce();//make our random number nonce
    char buffer[LENGTH];
    bool flag = true;
    string temp = "", ks = "";
    int port = 9594;
    int newSd = connect(port);
    
    //char msg[1500];//buffer to send and receive messages with

    while(flag){
        //receive a message from the client (listen)
        ks = getKs(bfb, newSd);
        BLOWFISH bfs(ks);//create new blowfish 
        
        if(nonceMaster(nonce,  bfs, newSd)){
            ready(bfs, newSd);
        }else{
            cout<<"exiting...\n";
            exit(1);
        }
        
        /*Receive File from Client */
		char* fr_name = "test4.txt";//where we are writing the file to. 
		FILE *fr = fopen(fr_name, "w");
        FILE *tempfp = fopen("rcvdstuff.txt", "w");
		if (fr == NULL){
			printf("File %s Cannot be opened file on server.\n", fr_name);
		}
        else{
            if(encryptOn){
                receiveEncryptedFile(bfs, newSd, fr);
            }
            else{
                receiveFile(bfs, newSd, fr);
            }
			fclose(fr);
		}
    close(newSd);
    flag = false;
    }
    return 0;   

}