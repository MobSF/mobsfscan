
byte[] text ="top_sec".getBytes();
byte[] iv ={
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
KeyGenerator kg = KeyGenerator.getInstance("DES");
kg.init(56);
SecretKey key = kg.generateKey();
Cipher cp = Cipher.getInstance("DES/CBC/PKCS5Padding");
IvParameterSpec ips = new IvParameterSpec(iv);
cp.init(Cipher.ENCRYPT_MODE, key, ips);
cp.doFinal(inpBytes);