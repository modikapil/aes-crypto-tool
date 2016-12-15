package com.key;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * 
 * @author kkumar8
 *
 */
public class KeyProviderImpl implements KeyProvider {

  public static final String SYMMETRIC_KEY_PASSWORD_FILENAME = ".symmetric.key.password.filename";
  public static final String SYMMETRIC_KEY_STORE_FILENAME = ".symmetric.key.store.filename";
  public static final String SYMMETRIC_KEY_STORE_TYPE = ".symmetric.key.store.type";
  public static final String SYMMETRIC_KEY_ALIAS = ".symmetric.key.alias";
  public static final String CLIENTS = "clients";

  private Map<String, SecretKey> symmetricKeys = new HashMap<>();
  private final Properties properties = new Properties();

  public KeyProviderImpl() {
    loadProperties();
    init();
  }

  private void init() {
    String clientList = properties.getProperty(CLIENTS);
    if (StringUtils.isNotBlank(clientList)) {
      Set<String> clients = Arrays.asList(clientList.split(",")).stream().collect(Collectors.toSet());
      symmetricKeys = clients.stream().collect(Collectors.toMap(k -> k.toLowerCase(), v -> loadSymmetricKey(properties, v.toLowerCase())));
    }
  }

  private Properties loadProperties() {
    try {
      final InputStream inputStream = KeyProviderImpl.class.getResourceAsStream("/restful.client.properties");
      properties.load(inputStream);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return properties;
  }

  private SecretKeySpec loadSymmetricKey(Properties properties, String client) {

    char[] keyStorePassword = getPassword(properties.getProperty(client + SYMMETRIC_KEY_PASSWORD_FILENAME));
    String keyStoreFilename = properties.getProperty(client + SYMMETRIC_KEY_STORE_FILENAME);
    String keyStoreType = properties.getProperty(client + SYMMETRIC_KEY_STORE_TYPE);
    String keyAlias = properties.getProperty(client + SYMMETRIC_KEY_ALIAS);

    KeyStore keyStore = getKeyStore(keyStoreFilename, keyStoreType, new String(keyStorePassword));
    return getKey(keyStore, keyAlias, keyStorePassword);
  }

  @Override
  public SecretKey getSymmetricKey(String client) {
    return symmetricKeys.get(checkClient(client.toLowerCase(), symmetricKeys));
  }

  private <T> String checkClient(String client, Map<String, T> collection) {
    if (!collection.isEmpty() && (StringUtils.isEmpty(client) || !collection.containsKey(client.toLowerCase()))) {
      throw new RuntimeException();
    }
    return client.toLowerCase();
  }

  private char[] getPassword(final String filename) {
    if (StringUtils.isEmpty(filename)) {
      throw new RuntimeException(new FileNotFoundException("Filename not specified for password file"));
    }

    final InputStream inputStream = KeyProviderImpl.class.getResourceAsStream(filename);
    if (inputStream != null) {
      BufferedReader br = null;
      try {
        br = new BufferedReader(new InputStreamReader(inputStream));
        String value;
        if ((value = br.readLine()) != null) {
          final byte[] decodedBytes = Base64.getDecoder().decode(value);
          final byte[] decryptedBytes = EncryptionEngine.decrypt(decodedBytes);
          return new String(decryptedBytes).toCharArray();
        }
        else {
          throw new RuntimeException(new FileNotFoundException("The following password file is empty " + filename));
        }

      }
      catch (Exception e) {
        e.printStackTrace();
      }
      finally {
        IOUtils.closeQuietly(br);
      }
    }
    else {
      throw new RuntimeException(new FileNotFoundException("Could not find password file " + filename));
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private <T> T getKey(final KeyStore keyStore, final String keyName, final char[] password) {
    T privateKey;
    try {
      privateKey = (T) keyStore.getKey(keyName, password);
      if (privateKey == null) {
        throw new RuntimeException("Private Key Null..");
      }
      return privateKey;
    }
    catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private KeyStore getKeyStore(String path, String type, String password) {
    KeyStore keyStore;
    final InputStream inputStream = KeyProviderImpl.class.getResourceAsStream(path);
    if (inputStream != null) {
      try {
        keyStore = KeyStore.getInstance(type);
        keyStore.load(inputStream, password.toCharArray());
        return keyStore;
      }
      catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    else {
      throw new RuntimeException(String.format("Could not find keystore %s", path));
    }
  }

}