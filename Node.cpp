#include "Node.h"
using namespace CryptoPP;

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
	std::cin>>temp;
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
	//generator
	std::random_device generator;
	//generator function
	std::mt19937_64 MerTwist(generator());
	//distribution layout
	std::uniform_int_distribution<long long int> distribution(0, std::llround(std::pow(2,64))-1);
	return distribution(MerTwist);	
}
