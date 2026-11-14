import java.io.File;
import java.io.FileInputStream;

class NativeBridgeModule {
    @ReactMethod
    public void readArbitraryFile(String path) throws Exception {
        // ruleid:android_rn_exposed_react_method
        FileInputStream fis = new FileInputStream(path);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String runCommand(String cmd) throws Exception {
        // ruleid:android_rn_exposed_react_method
        Runtime.getRuntime().exec(cmd);
        return "done";
    }

    @com.facebook.react.bridge.ReactMethod
    public void deleteTarget(String target) {
        // ruleid:android_rn_exposed_react_method
        File f = new File(target);
        f.delete();
    }

    public void internalHelperNotExposed(String path) throws Exception {
        // ok:android_rn_exposed_react_method
        File f = new File(path);
        // ok:android_rn_exposed_react_method
        new ProcessBuilder("ls").start();
    }

    @ReactMethod
    public void safeBridgeMethod(String label) {
        // ok:android_rn_exposed_react_method
        String normalized = label.trim();
    }
}
