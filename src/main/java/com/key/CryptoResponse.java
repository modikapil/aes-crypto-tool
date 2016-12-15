package com.key;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;

public class CryptoResponse {

	private final byte[] value;
	private final byte[] iv;

	public CryptoResponse(byte[] value, byte[] iv) {
		this.value = value;
		this.iv = iv;
	}

	public byte[] getValue() {
		return value;
	}

	public byte[] getIv() {
		return iv;
	}

	public String getValueAsString() {
		return new String(value, Charsets.UTF_8);
	}

	public String getValueEncoded() {
		return base64Encode(value);
	}

	public String getIVAsString() {
		return new String(iv, Charsets.UTF_8);
	}

	public String getIVEncoded() {
		return base64Encode(iv);
	}

	public static CryptoResponse build(byte[] value, byte[] iv) {
		return new CryptoResponse(value, iv);
	}

	public static String base64Encode(byte[] value) {
		return Base64.encodeBase64String(value);
	}

}
