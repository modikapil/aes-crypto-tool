package com.key;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;

public class CryptoServiceImpl implements CryptoService {

  private static final String CIPHER_TRANSFORMATION_NAME_AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5PADDING";

  KeyProvider keyProvider = new KeyProviderImpl();

  @Override
  public CryptoResponse encrypt(String value, String clientType) {
    return process(CryptoRequest.buildEncryptRequest(getUTF8Bytes(value), clientType));
  }

  @Override
  public String decodeThenDecrypt(String cipherTextEncoded, String clientType, String clientIVEncoded) {
    return decryptInternal(cipherTextEncoded, clientType, clientIVEncoded).getValueAsString();
  }

  private CryptoResponse decryptInternal(String cipherTextEncoded, String clientType, String clientIVEncoded) {
    return process(CryptoRequest.buildDecryptRequest(base64DecodeToByteArray(cipherTextEncoded), base64DecodeToByteArray(clientIVEncoded),
        clientType));
  }

  private CryptoResponse process(CryptoRequest cryptoRequest) {
    Cipher cipher = getCipher(cryptoRequest);
    byte[] cyptoByte;
    try {
      cyptoByte = cipher.doFinal(cryptoRequest.getValue());
    }
    catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException("Could not decrypt/encrypt value", e);
    }
    return CryptoResponse.build(cyptoByte, cipher.getIV());
  }

  private Cipher getCipher(CryptoRequest cryptoRequest) {
    SecretKey key = keyProvider.getSymmetricKey(cryptoRequest.getClientType());

    Cipher cipher;
    try {
      cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_NAME_AES_CBC_PKCS5_PADDING);
      if (cryptoRequest.getValue() != null) {
        cipher.init(cryptoRequest.getMethod(), key, new IvParameterSpec(cryptoRequest.getIV()));
      }
      else {
        cipher.init(cryptoRequest.getMethod(), key);
      }
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
      throw new RuntimeException(String.format("Could not create Cipher for %s", cryptoRequest.getClientType()), e);
    }
    return cipher;
  }

  public static byte[] getUTF8Bytes(String value) {
    return value.getBytes(Charsets.UTF_8);
  }

  public static byte[] base64DecodeToByteArray(String value) {
    return Base64.decodeBase64(value);
  }

}