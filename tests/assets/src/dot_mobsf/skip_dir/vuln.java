  final String MD5 = "MD5";
        // Create MD5 Hash
        MessageDigest digest = java.security.MessageDigest
                .getInstance(MD5);
        digest.update(s.getBytes());

    return "";
    java.security.MessageDigest
                .getInstance("MD5");

   try {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] array = md.digest(md5.getBytes("UTF-8"));
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < array.length; ++i) {
          sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
       }
        return sb.toString();
    } catch (java.security.NoSuchAlgorithmException e) {
    } catch(UnsupportedEncodingException ex){
    }
    return null;

    String hash = "35454B055CC325EA1AF2126E27707052";
    String password = "ILoveJava";

    String md5Hex = DigestUtils.md5Hex(password).toUpperCase();
        
    assertThat(md5Hex.equals(hash)).isTrue();



    String filename = "src/test/resources/test_md5.txt";
    String checksum = "5EB63BBBE01EEED093CB22BB8F5ACDC3";
        
    HashCode hash = com.google.common.io.Files
      .hash(new File(filename), Hashing.md5());
    String myChecksum = hash.toString()
      .toUpperCase();
        
    assertThat(myChecksum.equals(checksum)).isTrue();
    x.getInstance("md4");
