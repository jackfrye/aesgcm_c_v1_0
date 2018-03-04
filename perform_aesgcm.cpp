#include <stdio.h>
#include <iostream>
#include <string>
#include "hex.h"
#include "cryptlib.h"
#include "cryptopp/filters.h"
#include "aes.h"
#include "gcm.h"

using namespace std;

void perform_aesgcm(CryptoPP::byte *key,
					int key_size,
					CryptoPP::byte *iv,
					int iv_size,
					CryptoPP::byte *adata,
					int adata_size,
					CryptoPP::byte *plaintext,
					int plaintext_size,
					int tag_size,
					CryptoPP::byte *ciphertext) {

	string cipher;

	try {
		CryptoPP::GCM<CryptoPP::AES>::Encryption e;
		e.SetKeyWithIV(key, key_size, iv, iv_size);

		CryptoPP::AuthenticatedEncryptionFilter ef(e,
				new CryptoPP::StringSink(cipher), false, tag_size);

		ef.ChannelPut("AAD", adata, adata_size);
		ef.ChannelMessageEnd("AAD");

		ef.ChannelPut("", plaintext, plaintext_size);
		ef.ChannelMessageEnd("");
	}
	catch(CryptoPP::BufferedTransformation::NoChannelSupport& e)
	{
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
	}
	catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
	        // Pushing PDATA before ADATA results in:
	        //  "GMC/AES: Update was called before State_IVSet"
	        cerr << "Caught BadState..." << endl;
	        cerr << e.what() << endl;
	        cerr << endl;
	}
	catch( CryptoPP::InvalidArgument& e )
	{
	        cerr << "Caught InvalidArgument..." << endl;
	        cerr << e.what() << endl;
	        cerr << endl;
	}

	memcpy(ciphertext, cipher.c_str(), plaintext_size);
}
