#ifndef NODE_H
#define NODE_H

#include <vector>
#include <iostream>
#include <cstring>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <random>
#include <cmath>

class Node
{
	private:
	std::vector<CryptoPP::RSA::PublicKey> keys;
	int port;
	CryptoPP::RSA::PrivateKey privKey;

	public:
	//RSA key access functions
	bool addPubKey(CryptoPP::RSA::PublicKey key);
	bool removeKeyIndex(int index);
	int getVectorSize(void);
	CryptoPP::RSA::PublicKey getKey(int index);

	//console input output
	std::string getInput(void);
	void printOutput(std::string outp);

	//RSA encryption
	void generateKeysRSA(int keyLength);
	CryptoPP::Integer RSAencrypt(std::string message, CryptoPP::RSA::PublicKey pubKey);
	std::string RSAdecrypt(CryptoPP::Integer message);

	//std::string 3DESencrypt(std::string message);
	//std::string 3DESdecrypt(std::string message);

	//void sendPacket(char* message);
	//char* recievePacket(void);

	//networking methods
	//bool setPort(int port);
	//int getPort(void);

	//math
	long long int largeRandom(void);
	
};

#endif
