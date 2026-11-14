import java.io.FileInputStream;
public class BridgeModule {
  @ReactMethod
  public void readFile(String p) throws Exception {
    new FileInputStream(p);
  }
}
