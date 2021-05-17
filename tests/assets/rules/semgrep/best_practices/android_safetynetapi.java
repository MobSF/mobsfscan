import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;       
       
SafetyNetClient client = SafetyNet.getClient(getActivity());
Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, BuildConfig.API_KEY);