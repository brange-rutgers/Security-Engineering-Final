#import "Node.h"

enum states
{
	IDLE, WAITING_RESPONSE, WAIT_FOR_VERIFY, DATA_TRANS

};
global Node deviceNode;
int status = IDLE;

void simSwitch(){
//initialize
deviceNode.generateKeysRSA();
	while (true) {


		switch (status)

			case: IDLE
				idle();
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

	char* packet = listen(PORT);

	if (packet.type == hello) {

		// change packet to hello response
		send(SIM, packet);

		status = WAIT_FOR_VERIFY;
	}
	else {
		return;
	}


}


void wait_for_verify() {


	//listen on sim port
	char* packet = listen(PORT);

	//if packet was not sim cert, exit
	if (packet.type() == SIM_CERT) {
	
		char* simKeyData;
		for (int i = 0; i<PUBLIC_KEY_CHAR_LENGTH; ++i) {
			simKeyData[i] = packet[i + PUBLIC_KEY_START_INDEX];
		}

		//convert it to a proper PublicKey object
		CryptoPP::RSA::PublicKey *deviceKey = reinterpret_cast<CryptoPP::RSA::PublicKey*>(deviceKeyData);

		//sim's public key added to keylist at index 2
		mimNode.addPubKey(simKey);

		std::string aesPacket;


		deviceNode.generateKeysAES();

		// add keys to packet


		aesPacket = deviceNode.RSAencrypt(aesPacket, mimNode.getKey(2));

		char *sendMe = new char[aesPacket.length() + 1];
		std::strcpy(sendMe, aesPacket.c_str());

		send(SIM, sendMe);
		status = DATA_TRANS;
		

	}
	else {
		return;
	}


}


void data_trans() {




	while (true) {

		char* packet = listen(PORT);

		if (packet.type == close) {
			//close connection
			break;
		}


		std::string pacString(packet);
		pacString = deviceNode.AESdecrypt(pacString);


		//generate reponse into packet

		send(SIM, packet);

	}


}


