@Echo off
%cd%/jdk1.8.0_20/jre/bin/java -jar %cd%/AESEncryption.jar decrypt %cd%/payload/decrypt-parload.text nws %cd%/payload/decrypt-iv.txt > aes-decryption-nws.txt