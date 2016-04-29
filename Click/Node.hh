#ifndef CLICK_NODE_HH
#define CLICK_NODE_HH
#include <click/element.hh>
#include <vector>
#include <iostream>
#include <cstring>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/modes.h>
CLICK_DECLS
class Node : public Element
{
	public:
		Node(){}
		~Node(){}

		const char *class_name() const { return "Node";}
		const char *port_count() const { return "1/1"; }
		const char *processing() const { return PUSH; }
		int configure(Vector<String>&, ErrorHandler*){return 0;}
		void push(int port, Packet *);

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

	private:
		std::vector<CryptoPP::RSA::PublicKey> keys;
		int port;
		CryptoPP::RSA::PrivateKey privKey;
		CryptoPP::SecByteBlock aeskey;
		byte iv[CryptoPP::AES::BLOCKSIZE];


};
CLICK_ENDDECLS
#endif
