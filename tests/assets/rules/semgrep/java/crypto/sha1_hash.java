
    MessageDigest md = null;
    try {
        // ruleid:sha1_hash
        md = MessageDigest.getInstance("SHA-1");
    }
    catch(NoSuchAlgorithmException e) {
        e.printStackTrace();
    } 
    return new String(md.digest(convertme));

     // ruleid:sha1_hash
     String digest = DigestUtils.sha1Hex(is);
            System.out.println("Digest          = " + digest);
            System.out.println("Digest.length() = " + digest.length());