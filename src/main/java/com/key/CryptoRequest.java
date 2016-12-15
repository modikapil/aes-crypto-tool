package com.key;

import java.security.SecureRandom;

import javax.crypto.Cipher;

public class CryptoRequest {

	private final byte[] value;
	private final byte[] ivParameterSpec;
	private final String clientType;
	private final int method;

	private static final SecureRandom random = new SecureRandom();

	private CryptoRequest(byte[] value, byte[] ivParameterSpec, String clientType, int method) {
		super();
		this.value = value;
		this.ivParameterSpec = ivParameterSpec;
		this.clientType = clientType;
		this.method = method;
	}

	public byte[] getValue() {
		return value;
	}

	public byte[] getIV() {
		return ivParameterSpec;
	}

	public String getClientType() {
		return clientType;
	}

	public int getMethod() {
		return method;
	}

	public static SecureRandom getRandom() {
		return random;
	}

	public static CryptoRequest buildDecryptRequest(byte[] value, byte[] ivParameterSpec, String clientType) {
		return new CryptoRequest(value, ivParameterSpec, clientType.toLowerCase(), Cipher.DECRYPT_MODE);
	}

	public static CryptoRequest buildEncryptRequest(byte[] value, String clientType) {
		return new CryptoRequest(value, random.generateSeed(16), clientType.toLowerCase(), Cipher.ENCRYPT_MODE);
	}

	public static CryptoRequest buildEncryptRequest(byte[] value, byte[] ivParameterSpec, String clientType) {
		return new CryptoRequest(value, ivParameterSpec, clientType.toLowerCase(), Cipher.ENCRYPT_MODE);
	}

}
