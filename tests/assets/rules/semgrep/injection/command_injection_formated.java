import java.lang.Runtime;

class Cls {

    public Cls(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid:command_injection_warning
        r.exec("/bin/sh -c some_tool" + input);
    }

    public void test1(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid:command_injection_warning
        r.loadLibrary(String.format("%s.dll", input));
    }

    public void test2(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid:command_injection_warning
        r.exec("bash", "-c", input);
    }

    public void okTest(String input) {
        Runtime r = Runtime.getRuntime();
        // ok: command_injection_warning
        r.exec("echo 'blah'");
    }
}