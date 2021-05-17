

Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
Cipher cc = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
Cipher ccc = Cipher.getInstance("DES/CBC/PKCS5Padding");
Cipher cccc = Cipher.getInstance("AES/CBC/PKCS7Padding");
Cipher ccccc = Cipher.getInstance("Blowfish/CBC/PKCS7Padding");

// good
Cipher g = Cipher.getInstance("AES/GCM/NoPadding");

Cipher g1 = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding"); 
Cipher g2 = Cipher.getInstance("RSA/None/OAEPWITHSHA-256ANDMGF1PADDING");