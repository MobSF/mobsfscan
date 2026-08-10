// ruleid:java_insecure_random
import java.util.Random;
import java.security.SecureRandom;
class GenerateRandom {
    public static void main( String args[] ) {
      Random rand = new Random(); //instance of random class
      int upperbound = 25;
        //generate random values from 0-24
      int int_random = rand.nextInt(upperbound); 
      double double_random=rand.nextDouble();
      float float_random=rand.nextFloat();
      
      System.out.println("Random integer value from 0 to" + (upperbound-1) + " : "+ int_random);
      System.out.println("Random float value between 0.0 and 1.0 : "+float_random);
      System.out.println("Random double value between 0.0 and 1.0 : "+double_random);
    }
}

// ruleid:java_insecure_random
import java.util.concurrent.ThreadLocalRandom;
class GenerateRandom {
    public static void main( String args[] ) {
      // Generate random integers  
      int int_random = ThreadLocalRandom.current().nextInt();  
  
      // Print random integers 
      System.out.println("Random Integers: " + int_random); 

      // Generate Random doubles 
      double double_rand = ThreadLocalRandom.current().nextDouble(); 
      // Print random doubles 
      System.out.println("Random Doubles: " + double_rand); 
       
      // Generate random booleans 
      boolean boolean_rand = ThreadLocalRandom.current().nextBoolean(); 
       
      // Print random booleans 
      System.out.println("Random Booleans: " + boolean_rand); 
    }
}