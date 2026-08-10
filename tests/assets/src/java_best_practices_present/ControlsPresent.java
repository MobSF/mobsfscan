import com.google.android.gms.safetynet.SafetyNetApi;

import android.view.View;
import android.view.WindowManager;

import okhttp3.CertificatePinner;

class ControlsPresent extends Activity {
    void enableControls(View view, Device device) {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        device.isDeviceRooted();
        view.setFilterTouchesWhenObscured(true);
        new CTInterceptorBuilder();
        new CertificatePinner.Builder();
    }
}
