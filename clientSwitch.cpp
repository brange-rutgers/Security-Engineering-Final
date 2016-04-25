#import "Node.h"

enum states
{
	IDLE, WAITING_RESPONSE, WAIT_FOR_VERIFY, DATA_TRANS
	
};
global Node simNode;
int status = IDLE;

void simSwitch(){
//initialize
simNode.generateKeysRSA();
	while (;;) {


		switch (status)

			case: IDLE
				idle();
				break;
			case: WAITING_RESPONSE
				wait_response();
				break;
			case: WAIT_FOR_VERIFY
				wait_for_verify();
				break;
			case: DATA_TRANS
				data_trans()
				break;

	}
}

void idle() {

	// wait for trigger to initiate
	//send request
	send(DEVICE, packet);

	status = WAITING_RESPONSE;

	return;
}


void wait_response() {

	// waiting for hello response from server

	char* packet = listen(PORT);

	if (packet.type == HELLO_RESP) {
		//send key


		CryptoPP::RSA::PublicKey SIMPubKey = simNode.getKey(0);
		char *SIMPubData = reinterpret_cast<char*>(&SIMPubKey);


		for (int i = 0; i < PUBLIC_KEY_CHAR_LENGTH; ++i) {
			packet[i + PUBLIC_KEY_START_INDEX] = SIMPubData[i];
		}


		send(DEVICE, packet);
		status = WAIT_FOR_VERIFY;


	}
	else {
		return;
	}
}

void wait_for_verify() {

	char* packet = listen(PORT);

	if (packet.type == AES_TRANSMIT) {

		//decrypt the packet & convert to char*
		std::string aesPacket = simNode.RSAdecrypt();
		const char* cAesPacket = aesPacket.c_str();


		//extract the first part of the AES key
		char* secByteBlockData;
		for (int i = 0; i < SEC_BYTE_BLOCK_CHAR_LENGTH; ++i) {
			secByteBlockData[i] = cAesPacket[i + SEC_BYTE_BLOCK_CHAR_OFFSET];
		}

		//extract the second part of the AES key
		char* byteData;
		for (int i = 0; i < BYTE_DATA_CHAR_LENGTH; ++i) {
			byteData[i] = cAesPacket[i + BYTE_DATA_CHAR_OFFSET];
		}


		//convert them to proper type
		CryptoPP::SecByteBlock *aesKey = reinterpret_cast<CryptoPP::SecByteBlock*>(secByteBlockData);
		byte *byteKey = reinterpret_cast<byte*>(data);

		//store the keys
		simNode.setKeysAES(aesKey, byteKey);

		status = DATA_TRANS;
		return;
	}
	else {
		return;
	}

}




void data_trans() {

	char* packet; // some input

	send(DEVICE, packet);


	while (;;) {


		if (close_flag) {
			break;
		}
		char* packet = listen(PORT);

		//read/interperet
		std::string pacString(packet);
		pacString = mimNode.AESdecrypt(pacString);

		// modify packet for a response
		send(DEVICE, packet);

	}


	//set packet to close type

	send(DEVICE, packet);



}

