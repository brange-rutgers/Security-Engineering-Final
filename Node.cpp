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
bool Node::removeKey(RSA::PublicKey key){
	int temp=getVectorSize();
	for(int i=0; i<getVectorSize(); ++i){
		if(keys.at(i)==key){
			keys.erase(keys.begin()+i);
			if(temp>getVectorSize()){
				return 1;
			}
		}
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
	if(index<getVectorSize()){
		return keys.at(index);
	}
	return NULL;
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

void generateKeysRSA(int keyLength){
	privKey.GenerateRandomWithKeySize(prng, keyLength);
	RSA::PublicKey pubKey(privKey);
	addKey(pubKey);
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
