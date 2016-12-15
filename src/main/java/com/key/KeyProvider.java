package com.key;

import javax.crypto.SecretKey;

public interface KeyProvider {

	SecretKey getSymmetricKey(String client);

}
