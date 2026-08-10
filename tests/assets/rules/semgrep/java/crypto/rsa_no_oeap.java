 // ruleid:rsa_no_oeap
 Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
 KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

Cipher rsa = null;
try {
// ruleid:rsa_no_oeap
rsa = javax.crypto.Cipher.getInstance("RSA/NONE/NoPadding");
}
catch (java.security.NoSuchAlgorithmException e) {
log("this should never happen", e);
}
catch (javax.crypto.NoSuchPaddingException e) {
log("this should never happen", e);
}
return rsa;