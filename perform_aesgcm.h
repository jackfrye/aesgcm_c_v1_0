#include <stdio.h>
#include <iostream>
#include <string>
#include "hex.h"
#include "cryptlib.h"
#include "cryptopp/filters.h"
#include "aes.h"
#include "gcm.h"

void perform_aesgcm(CryptoPP::byte *key,
					int key_size,
					CryptoPP::byte *iv,
					int iv_size,
					CryptoPP::byte *adata,
					int adata_size,
					CryptoPP::byte *plaintext,
					int plaintext_size,
					int tag_size,
					CryptoPP::byte *ciphertext);
