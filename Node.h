#ifndef NODE_H
#define NODE_H

#include <vector>
#include <iostream>
#include <cstring>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/modes.h>
#include <random>
#include <cmath>

class Node
{
	public:
	//keys and ports
	std::vector<CryptoPP::RSA::PublicKey> keys;
	int port;
	CryptoPP::RSA::PrivateKey privKey;
	CryptoPP::SecByteBlock aeskey;
	byte iv[CryptoPP::AES::BLOCKSIZE];

	//RSA key access functions
	bool addPubKey(CryptoPP::RSA::PublicKey key);
	bool removeKeyIndex(int index);
	int getVectorSize(void);
	CryptoPP::RSA::PublicKey getKey(int index);

	//AES key returns
	CryptoPP::SecByteBlock getSecByteBlock(void);
	byte* getiv(void);
	void setKeysAES(CryptoPP::SecByteBlock key1, byte key2[CryptoPP::AES::BLOCKSIZE]);
	

	//console input output
	std::string getInput(void);
	void printOutput(std::string outp);

	//RSA encryption
	void generateKeysRSA(int keyLength);
	CryptoPP::Integer RSAencrypt(std::string message, CryptoPP::RSA::PublicKey pubKey);
	std::string RSAdecrypt(CryptoPP::Integer message);

	void generateKeysAES(void);
	std::string AESencrypt(std::string message);
	std::string AESdecrypt(std::string message);

	//void sendPacket(char* message);
	//char* recievePacket(void);

	//networking methods
	//bool setPort(int port);
	//int getPort(void);

	//math
	long long int largeRandom(void);
	
};

#endif
