#include <click/config.h>
//#include <random>
#include <cstdlib>
#include <climits>
#include <ctime>
#include <sstream>
#include "Node.hh"
using namespace CryptoPP;
CLICK_DECLS

enum ENCRYPTIONCHOICE
{
	ENCRYPT = 0,
	DECRYPT = 1,
	PASSTHROUGH = 2
};

std::string CryptoIntegerToString(Integer i)
{
	std::ostringstream stream;
	stream << i;
	return stream.str();
}

void Node::push(int port, Packet *p)
{
	int encrypt = ENCRYPT;
	WritablePacket * w;
	Integer i;
	unsigned int key_index = 0;
	
	unsigned int new_packet_size = p->length();

	std::string message = std::string((const char *) p->data(), p->length());

	if (this->getVectorSize() <  1)
	{
		generateKeysRSA(50);
	}

	if (encrypt == ENCRYPT)
	{
		i = this->RSAencrypt(message, this->getKey(key_index));
		std::string encrypted_string = CryptoIntegerToString(i);
		new_packet_size = encrypted_string.length();
		w = Packet::make(encrypted_string.c_str(), new_packet_size);
		p->kill();
		output(port).push(w);
	}
	else if (encrypt == DECRYPT)
	{
		i = this->RSAencrypt(message, this->getKey(key_index));
		w = Packet::make(p->data(), new_packet_size);
		p->kill();
		output(port).push(w);
	}
	else if (PASSTHROUGH)
	{
		output(port).push(p);		
	}
	else
	{
		p->kill();
	}
}

bool Node::addPubKey(RSA::PublicKey key){
	int temp=getVectorSize();
	keys.push_back(key);
	if(temp<getVectorSize()){
		return 1;
	}
	return 0;
}

bool Node::removeKeyIndex(int index){
	int temp=getVectorSize();
	keys.erase(keys.begin()+index);
	if(temp>getVectorSize()){
		return 1;
	}
	return 0;
}

int Node::getVectorSize(void){
	return keys.size();
}

RSA::PublicKey Node::getKey(int index){
	return keys.at(index);
	//very unsafe to out of range index
	//however, RSA::PublicKey does not support a Null Key
}

std::string Node::getInput(void){
	std::string temp;
	std::getline(std::cin,temp);
	return temp;
}
void Node::printOutput(std::string outp){
	std::cout<<outp<<"\n";
	return;
}

void Node::generateKeysRSA(int keyLength){
	AutoSeededRandomPool prng;
	privKey.GenerateRandomWithKeySize(prng, keyLength);
	RSA::PublicKey pubKey(privKey);
	addPubKey(pubKey);
}

Integer Node::RSAencrypt(std::string message, RSA::PublicKey pubKey){
	Integer raw((const byte*)message.data(), message.size());
	raw=pubKey.ApplyFunction(raw);
	return raw;
}
std::string Node::RSAdecrypt(Integer raw){
	AutoSeededRandomPool prng;
	raw = privKey.CalculateInverse(prng, raw);

	std::string recovered;
	recovered.resize(raw.MinEncodedSize());
	raw.Encode((byte *)recovered.data(), recovered.size());	
	return recovered;
}

long long int Node::largeRandom(void){
/*	//generator
	std::random_device generator;
	//generator function
	std::mt19937_64 MerTwist(generator());
	//distribution layout
	std::uniform_int_distribution<long long int> distribution(0, std::llround(std::pow(2,64))-1);
	return distribution(MerTwist);
*/	std::srand(std::time(0)); 
	long long int r = static_cast<double>(std::rand()) / RAND_MAX * LLONG_MAX + 1;
	return r;
}

void Node::generateKeysAES(void){
	AutoSeededRandomPool rnd;
	aeskey=SecByteBlock(0x00, AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock( aeskey, aeskey.size() );
	rnd.GenerateBlock(iv, AES::BLOCKSIZE);
	return;
}

std::string Node::AESencrypt(std::string message){
	//convert string to char*
	char *messagec = new char[message.length() + 1];
	strcpy(messagec, message.c_str());

	CFB_Mode<AES>::Encryption cfbEncryption(aeskey, aeskey.size(), iv);
	int messageLen = (int)strlen(messagec) + 1;
	cfbEncryption.ProcessData((byte*)messagec, (byte*)messagec, messageLen);
	std::string retme(messagec);
	delete messagec;
	return retme;
}

std::string Node::AESdecrypt(std::string message){
	//convert string to char*
	char *messagec = new char[message.length() + 1];
	strcpy(messagec, message.c_str());

	CFB_Mode<AES>::Decryption cfbDecryption(aeskey, aeskey.size(), iv);
	int messageLen = (int)strlen(messagec) + 1;
	cfbDecryption.ProcessData((byte*)messagec, (byte*)messagec, messageLen);
	std::string retme(messagec);
	delete messagec;
	return retme;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel|ns)
EXPORT_ELEMENT(Node)
ELEMENT_LIBS((-L/usr/lib -lcryptopp))
