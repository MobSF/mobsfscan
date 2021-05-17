KeyPairGenerator kp = KeyPairGenerator.getInstance("RSA");
kp.initialize(512);

KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(64);

KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
keyGen.init(64);

KeyPairGenerator kp2 = KeyPairGenerator.getInstance("EC");
ECGenParameterSpec ep = new ECGenParameterSpec("secp112r1");
kp2.initialize(ep);

// good
KeyPairGenerator gp = KeyPairGenerator.getInstance("RSA");
gp.initialize(4096);

KeyPairGenerator gp3 = KeyPairGenerator.getInstance("EC");
ECGenParameterSpec sp2 = new ECGenParameterSpec("secp224k1");
gp3.initialize(sp2);
