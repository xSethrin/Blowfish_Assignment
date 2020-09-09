/**
RUN THIS ONE ON THING0
*/
#include <iostream>
#include <string>
#include <cerrno> 
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
#include "blowfisha.cpp"
#include "blowfish.cpp"
#include "blowfishb.cpp"


bool mode = true;
#define LENGTH 1500
using namespace std;
typedef unsigned char byte;
using namespace std;
//Client side
/**
    This is used to create meaningful error messages. 
*/
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


/**
    This method will conduct the agreed upon math to nonce for validation. 
    @nonce this is the nonce that will be maniputlated to obtain response. 
    @returns a long that will be used for validation. 
*/
long f(long nonce) {
    const long A = 48271;
    const long M = 2147483647;
    const long Q = M/A;
    const long R = M%A;
	static long state = 1;
	long t = A * (state % Q) - R * (state / Q);
	if (t > 0){
		state = t;
    }else{
		state = t + M;
    }
	return (long)(((double) state/M)* nonce);
}
/**
    This method was used to generate a random number for out nonce testing. 
    @returns a type long. 
*/
long randomNonce(){
    long nonce = 1;
    int x = 0;
    for(int i = 0; i <= 5; i++){
        x = rand();
        nonce = (nonce + nonce) * x;
    }
    return nonce;
}
/**
    This method will create a connection.
    @serverIp The ipAdress of the to server to connect to 
    @port the port you wish to connect to. 
    @returns an int. 
*/
int connect(char* serverIp, int port){

    //create a message buffer 
    char msg[1500]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = 
        inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,(sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0){
        cout<<"Error connecting to socket!"<<endl;
       exit(1);
        return clientSd;
    }
    else{
        cout << "Connected to the server!" << endl;
        return clientSd;
    }
}
/**
    This function will talk to the kdc and get the Eka[Ks||N1||Ekb(Ks,iDA)]
    @clientSd the connectin to KDC
    @bfa This is the blowfish object that will read encrpyted stuff
    @nonce this is the nonce that will be sent to the KDC
    @returns a string that is the Ks and iDA to send to Actor B. 
*/
string KDCExchange(int clientSd, BLOWFISHA bfa, long nonce, string &ks){
    int n = 0;
    string temp = "", snonce = "", package= "", checkNonce = "",aID="";
    snonce = to_string(nonce);//making a string out of nonce. 
    char key[LENGTH];//request for a package
    bzero(key,LENGTH);
    strcpy(key, snonce.c_str());//make the request 
    
    cout<<"Sending request to KDC for Ks for IDb\n"<<"N1: "<<snonce<<endl;
    n = write(clientSd, key, strlen(key));//writing to KDC the request||N1
    if (n < 0) error("ERROR reading from socket");
    bzero(key,1500);//zeroing out key
    //cout<<"This is the key after sending and clearing before read"<<endl;
    //cout<<key<<endl;
    //cout<<key<<"1"<<endl; //this was a test line.
    int count = 0;
    int fs_block_sz;   
    while ((fs_block_sz = read(clientSd, key, sizeof(key))) > 0){     //reading from KDC the encrypted Ks||request||N1||Kb(KS,IDa)
        int i = 0;
            while(i < sizeof(key)+1){
                if(key[i] == '$'){
                    //temp = bfa.Decrypt_CBC(temp);
                    if(count == 0){//getting the session key
                        ks = temp;
                        cout<<"Recived Ks: "<<ks<<endl;
                    }
                    else if(count == 1){//getting the nonce 
                        checkNonce = temp;
                        cout<<"Recived N1: "<<checkNonce<<endl;
                    }
                    else if(count == 2){//getting the 
                        package = temp;
                    }
                    else if(count == 3){
                        aID = temp;
                    }
                    temp.clear();
                    count++;
                }else{
                    temp = temp + key[i];
                }
                i++;
            }
    }
    bzero(key,LENGTH);
    
    ks = bfa.Decrypt_CBC(ks);//decrypting Ks with blowfish A
    checkNonce = bfa.Decrypt_CBC(checkNonce);//decrypting the nonce with blowfish A
    package = bfa.Decrypt_CBC(package);//decrypting Ks to send to participant B(still encrypted with bfb)
    aID = bfa.Decrypt_CBC(aID);//decrypting aID to send to B(still encrypted with bfb)
    temp.clear();
    package = package + "$" + aID + "$";
    cout<<"Sending to IDb: "<<package<<endl;
    if(snonce.compare(checkNonce) != 0 ){
        cout << "nonce check failed\nexiting...\n";
        exit(1);
    }
    return package;
}





/**
    This method will exchange the nonce with Actor B
    @clientSd this is the connection to B
    @bfs this is the blowfish with ks entered
    @fs_name the name of the file system
    @package the string of the Ks and the iDA encryped with Kb

*/
void bHandShake(int clientSd, BLOWFISH bfs,string package){
    int fs_block_sz;   
    int n = 0;
    long nonce;
    char key[LENGTH];//request for a package
	string temp = "", snonce = "",checkNonce = "", aID="";
    strcpy(key, package.c_str());//copy package to char array to send to B
    n = write(clientSd, key, package.length());//send cool stuuff to B
    //cout<<key<<endl;
    if (n < 0) error("ERROR writting to the socket");//check if successful
    bzero(key,LENGTH);//zero out "key"
    n = read(clientSd, key, LENGTH);//read the nonce from B
	if (n < 0) error("ERROR reading from socket");//cheak for errors again -.-
    checkNonce = key;//set key to checkNonce
    cout<<"Received encrypted N2: "<<checkNonce<<endl;
    checkNonce = bfs.Decrypt_CBC(checkNonce);//decrypt with ks
    cout<<"Decrypted N2: "<<checkNonce<<endl;
    nonce = std::stol(checkNonce, 0);
    nonce = f(nonce);
    cout<<"Calculated f(N2): "<<nonce<<endl;
    snonce = to_string(nonce);
    snonce = bfs.Encrypt_CBC(snonce);
    strcpy(key, snonce.c_str());
    cout<<"Sending encrypted f(N2): "<<snonce<<endl;
    n = write(clientSd, key, LENGTH);
    if (n < 0) error("ERROR writting to the socket");//check if successful
    n = read(clientSd, key, LENGTH);//read the nonce from B
	if (n < 0) error("ERROR reading from socket");//cheak for errors again -.-
    string ready = key;
   if(ready.compare(ready) != 0 ){//check if ready was achieved 
            cout << "nonce check failed\nexiting...\n";
            exit(1);
    }
	if (n < 0) {
		printf("Error: sending. ");
        exit(1);
	}
	
}

/**
    This functino will send the file encryped with Ks over to Actor B
    @clientSd the connection
    @bfs the blowfish that has Ks as its key
    @fs_name the name of the file to be sent. 
*/
void sendFile(int clientSd,BLOWFISH bfs, char* fs_name){
    char array[1500];
    char sdbuf[LENGTH];
    bzero(sdbuf, LENGTH);
    string temp = "";
    int temp_length = 0;
    int fs_block_sz;  
    FILE *fs = fopen(fs_name, "r");
	if (fs == NULL){
		printf("ERROR: File %s not found.\n", fs_name);
		exit(1);
	}
    printf("[Client] Sending %s to the Server...\n ", fs_name);
	while ((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0){   
        if (mode){//to encrypt
            temp = sdbuf;//getting stuff out of the buffer
            temp = bfs.Encrypt_CBC(temp);//encrypting stuff
            temp = temp + "$";
            char array[temp.length()+1];
            strcpy(array, temp.c_str());
            temp_length = temp.length();
            //cout << temp_length << "\n\n";
            //cout << "array:\n" << array << "\n\n";
            if (send(clientSd, array, temp.length(), 0) < 0){
			    fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs_name, errno);
			    exit(1);
		    }
            bzero(array, temp_length);
        }
        else{//we are not encrypting 
            if (send(clientSd, sdbuf, fs_block_sz, 0) < 0){
                fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs_name, errno);
            }
        }
		bzero(sdbuf, LENGTH);
	}
    fclose(fs);
	printf("Ok File %s from Client was Sent!\n", fs_name);
	
	printf("[Client] Connection lost.\n");
}

/**
    This program will create a connection with KDC and get a session key and then send over a file. 
*/
int main(int argc, char *argv[]) {
	//BLOWFISHB bfb("ABC123XYZ456GHYF");//creating blowfish with Kb ????
    cout<<"Blowfish keys must only contain letters and numbers.  They must be a length divisible by 8.\nNonce must be at most 16 digits long."<<endl;
    string bfaKey = keyPrompt("Key A");
    BLOWFISHA bfa(bfaKey);//creates blowfish for Ka
    string ks = "";
    long nonce = noncePrompt("nonce");//randomNonce();//will need to prompt for this. 
	int clientSd = 0;//keeps conncetion to server
    char *serverIp = "10.35.195.47";//thing1 //server connection of KDC
    int port = 9475;//port to connect to needs to be the same as KDC
    char fs_name[LENGTH];//what file are we sending
    bzero(fs_name,LENGTH);
    string package="";
    //creating the connection to KDC
    clientSd = connect(serverIp, port);//connect to kdc
    package = KDCExchange(clientSd,bfa, nonce,ks); //exchage with KDC and gets the package to send to Actor B. (encrytped with B)
    //cout<<"This is ks :"<<ks<<endl;
    close(clientSd);//close connection with KDC
    serverIp = "10.35.195.49";//thing 3 Acotor B(server)
    port = 9594;
    clientSd = connect(serverIp, port);//create connection with bottom
    BLOWFISH bfs(ks);//creat new blowfish with ks
    bHandShake(clientSd,bfs,package);
    //sending the file.
    
    printf("Enter a Filename to send(an invlaid file will exit program): ");//asking user for input
	scanf("%s", &fs_name);//grabbing user input
    sendFile(clientSd,bfs,fs_name);
    close(clientSd);
	
    return 0;    
}