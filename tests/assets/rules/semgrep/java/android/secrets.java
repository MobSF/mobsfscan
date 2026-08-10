package jwt_test.jwt_test_1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

public class App
{

    // ruleid:hardcoded_secret
    static String secret = "secret";
    String password;
    // ruleid:hardcoded_password
    static String ppassword = "secret";

    private static void bad1() {
        try {
          
            Algorithm algorithm = Algorithm.HMAC256("secret");
            Foo.algorithm("password", "");
            // ruleid:hardcoded_password
            foo.password = "aasas";
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

    private static void ok1(String secretKey) {
        try {
            // ok: hardcoded_password
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

    public static void main( String[] args )
    {
        bad1();
        ok1(args[0]);
    }
}

abstract class App2
{

    // ruleid:hardcoded_secret
    static String secret = "secret";

    public void bad2() {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

}
