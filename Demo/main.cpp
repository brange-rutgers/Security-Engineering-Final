#include "Node.h"
#include <sstream>
using namespace std;
using namespace CryptoPP;
std::string printKey(RSA::PublicKey pk){
	int size = sizeof(pk);
	 char* simpd= (char*)(&pk);
	char buf[32];
	string s="";
	for(int i = 0; i<size; ++i){
		sprintf(buf, "%02x", simpd[i]);
		buf[2]=0;
		s+=buf;
	}
	return s;
}
string printdata(char* data, int length){
	std::ostringstream stream;
	char buf[32];
	for(int i=0; i<length;++i){
		memset(buf, 0, 32);;
		sprintf(buf, "%02x", data[i]);
		stream<<buf;
	}
	return stream.str();

}

int main(){
	Node device;
	Node sim;
	Node mitm;
	getchar();
	cout<<"SIM: Request to device, TLS, with RSA and AES\n\n";

	device.generateKeysRSA(2048);
	sim.generateKeysRSA(2048);
	mitm.generateKeysRSA(2048);
	getchar();
	//Server sends cert to sim, mitm forwards
	RSA::PublicKey devCert = device.getKey(0);
	cout<<"Device: Sent device public cert towards SIM\n";
	mitm.addPubKey(devCert);
	
	std::cout<<printKey(devCert)<<"\n";

	getchar();
	cout<<"!!! MITM: Intercepts from device, records, and forwards device public cert to SIM\n";
	sim.addPubKey(devCert);
	getchar();
	cout<<"SIM: Recieved device public cert, verifies that the device cert is from an authorized certificate authority\n";
	getchar();
	RSA::PublicKey simCert = sim.getKey(0);
	cout<<"SIM: Sent sim public cert towards device\n";
	mitm.addPubKey(simCert);
	std::cout<<printKey(simCert)<<"\n";
	getchar();
	RSA::PublicKey mitmCert = mitm.getKey(0);
	cout<<"!!! MITM: Recieved and blocked sim public cert\nForwarded MITM public cert to device instead\n";
	std::cout<<printKey(mitmCert)<<"\n";
	getchar();
	device.addPubKey(mitmCert);
	cout<<"\n ----CERT EXCHANGE COMPLETE----\n\n";
	getchar();
	device.generateKeysAES();
	cout<<"Device: generated Premaster secret, used to make AES keys\n!!!Encrypted with MITM public cert";
	getchar();
	string is = "AES Keys are : [ABCDE... Some random value]\n";
	SecByteBlock key = device.aeskey;
	char* c = reinterpret_cast<char*>(&key);
	printdata(c, sizeof(key));
	getchar();
	cout<<"The unencrypted message is : "<<is;
	Integer i = device.RSAencrypt(is, device.getKey(1));
	is=string(reinterpret_cast<char*>(&i));
	getchar();
	cout<<"The encrypted message from device with MITM public key is : "<<is<<"\n";

	getchar();	
	is=mitm.RSAdecrypt(i);
	cout<<"!!! MITM decrypts using MITM private key : "<<is;

	getchar();	i=mitm.RSAencrypt(is, mitm.getKey(2));
	mitm.generateKeysAES();
	mitm.aeskey=device.aeskey;
	memcpy(mitm.iv, device.iv, sizeof(device.iv));
	is=string(reinterpret_cast<char*>(&i));
	cout<<"!!! MITM recrypts using sim public key : "<<is<<"\n";

	getchar();	is=sim.RSAdecrypt(i);
	cout<<"SIM decrypts using its private key to : "<<is;
	getchar();
	sim.generateKeysAES();
	sim.aeskey=mitm.aeskey;
	memcpy(sim.iv, mitm.iv, sizeof(mitm.iv));

	string q = "Bob, here are my banking details. Please be careful with them.\n";
	getchar();
	std::cout<<"From device : "<<q;
	q=device.AESencrypt(q);
	getchar();
	std::cout<<"AES encrypted message : ";

	getchar();	cout<<q<<"\n!!! MITM forwards to sim\n";
	getchar();
	string r=mitm.AESdecrypt(q);
	std::cout<<"!!! MITM intercepted message : "<<r<<"\n";
	getchar();
	q=sim.AESdecrypt(q);
	std::cout<<"SIM recieve message : "<<q<<"\n";
	getchar();
	cout<<"\n\nEnter input for sim to send to device: \n";
	string str;
	getline(cin, str);
	str = sim.AESencrypt(str);
	cout<<"AES encrypted output from sim : "<<str<<"\n";
	getchar();
	cout<<"\n!!! MITM recieves : "<<str<<" and decrypts to : "<<mitm.AESdecrypt(str)<<"\n";
	getchar();
	cout<<"\nDevice recieves : "<<str<<" and decrypts to : "<<device.AESdecrypt(str)<<"\n";

	getchar();
}
