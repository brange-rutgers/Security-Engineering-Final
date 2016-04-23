




std::string 3DESencrypt(std::string message);
std::string 3DESdecrypt(std::string message);



SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
byte iv[DES_EDE3::BLOCKSIZE];


void 3DESgenKey() {

	AutoSeededRandomPool prng;
	
	prng.GenerateBlock(key, key.size());

	prng.GenerateBlock(iv, sizeof(iv));

	
}


std::string 3DESencrypt(std::string message) {

	CBC_Mode< DES_EDE3 >::Encryption e;
	e.SetKeyWithIV(key, key.size(), iv);

	string cipher;

	StringSource(message, true,
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		)
	);



	return cipher;
}


std::string 3DESdecrypt(std::string message) {

	CBC_Mode< DES_EDE3 >::Decryption d;
	d.SetKeyWithIV(key, key.size(), iv);

	StringSource s(message, true,
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource

	return recovered;




}










