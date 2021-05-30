import com.google.android.gms.safetynet.SafetyNet;
// ruleid:android_safetynet_api
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;       
       
// ruleid:android_safetynet_api
SafetyNetClient client = SafetyNet.getClient(getActivity());
Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, BuildConfig.API_KEY);