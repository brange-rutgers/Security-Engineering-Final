#ifndef NODE_H
#define NODE_H
 

#include <vector>
#include <iostream>
#include <cstring>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>

class Node
{
	private:
	std::vector<CryptoPP::RSA::PublicKey> keys;
	int port;
	CryptoPP::RSA::PrivateKey privKey;


	public:
	//key functions
	bool addKey(std::string key);
	bool removeKey(std::string key);
	bool removeKeyIndex(int index);
	int getVectorSize(void);
	std::string getKey(int index);
	void listKeys(void);

	CryptoPP::Integer RSAencrypt(std::string message);
	std::string RSAdecrypt(CryptoPP::Integer message);

	std::string 3DESencrypt(std::string message);
	std::string 3DESdecrypt(std::string message);

	void sendPacket(char* message);
	char* recievePacket(void);

	bool setPort(int port);
	int getPort(void);

	std::string getInput(void);
	void printOutput(std::string outp);
};

#endif
