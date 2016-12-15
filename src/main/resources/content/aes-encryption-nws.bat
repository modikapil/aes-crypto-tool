@Echo off
%cd%/jdk1.8.0_20/jre/bin/java -jar %cd%/AESEncryption.jar encrypt %cd%/payload/encrypt-payload.txt nws > aes-encryption-nws.txt