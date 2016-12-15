package com.key;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * 
 * @author kkumar8
 *
 */
public class AESUtil {

  private static CryptoServiceImpl cryptoServiceImpl;
  private static String content;
  private static String IV;

  static {
    cryptoServiceImpl = new CryptoServiceImpl();
  }

  public static void main(String[] args) {

    if (args.length == 3 && args[0].equalsIgnoreCase("encrypt")) {
      readPayloadAsFile(args[1]);
      encryptRequest(content, args[2]);
    }
    else if (args.length == 4 && args[0].equalsIgnoreCase("decrypt")) {
      readPayloadAsFile(args[1]);
      readIVAsFile(args[3]);
      decryptRequest(content, args[2], IV);
    }
    else {
      System.out.println("Something went wrong...");
    }

  }

  private static String readPayloadAsFile(String path) {
    try {
      content = new String(Files.readAllBytes(Paths.get(path)));
    }
    catch (IOException e) {
      e.printStackTrace();
    }
    return content;
  }

  private static String readIVAsFile(String path) {
    try {
      IV = new String(Files.readAllBytes(Paths.get(path)));
    }
    catch (IOException e) {
      e.printStackTrace();
    }
    return IV;
  }

  private static void encryptRequest(String value, String clientType) {
    CryptoResponse cryptoResponse = cryptoServiceImpl.encrypt(value, clientType);
    System.out.println("Client_Type: " + clientType.toUpperCase()
        + " Encrypted_Payload: "
        + cryptoResponse.getValueEncoded()
        + " Encrypted_IV: "
        + cryptoResponse.getIVEncoded());
  }

  private static void decryptRequest(String value, String clientType, String IV) {
    System.out.println("Client_Type: " + clientType.toUpperCase()
        + " Decoded_and_Decrypted_Value: "
        + cryptoServiceImpl.decodeThenDecrypt(value, clientType, IV));
  }

}