   
    // ruleid:aes_hardcoded_key
    SecretKeySpec secret = new SecretKeySpec("hardcoded".getBytes(), "AES"); 
       cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
   cipher.init(Cipher.ENCRYPT_MODE, secret); 
   //good
    SecretKeySpec secret = new SecretKeySpec(password.getBytes(), "AES"); 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException 
   /* Encrypt the message. */
   Cipher cipher = null; 
   cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
   cipher.init(Cipher.ENCRYPT_MODE, secret); 
   byte[] cipherText = cipher.doFinal(message.getBytes("UTF-8")); 
   return cipherText; 

    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException 
    /* Decrypt the message, given derived encContentValues and initialization vector. */
    Cipher cipher = null;
    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secret); 
    String decryptString = new String(cipher.doFinal(cipherText), "UTF-8");
    return decryptString; 
