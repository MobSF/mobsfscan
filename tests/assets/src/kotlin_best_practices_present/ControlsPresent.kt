
import android.view.WindowManager
import com.google.android.gms.safetynet.SafetyNet
import okhttp3.CertificatePinner

fun enableControls(window: android.view.Window, view: android.view.View, device: Device) {
    SafetyNet.getClient(context).attest(nonce, apiKey)
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    device.isDeviceRooted()
    view.setFilterTouchesWhenObscured(true)
    CTInterceptorBuilder()
    CertificatePinner.Builder().add("example.com", "sha256/AAA=").build()
}
