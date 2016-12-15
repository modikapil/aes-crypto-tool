package com.key;

public interface CryptoService {
	
	public CryptoResponse encrypt(String value, String clientType);
	
	public String decodeThenDecrypt(String cipherTextEncoded, String clientType, String clientIVEncoded);

}
