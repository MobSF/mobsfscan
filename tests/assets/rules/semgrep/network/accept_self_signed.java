// ruleid:accept_self_signed_certificate
HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

DefaultHttpClient client = new DefaultHttpClient();

SchemeRegistry registry = new SchemeRegistry();
SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
registry.register(new Scheme("https", socketFactory, 443));
SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());

// Set verifier     
HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);

// Example send http request
final String url = "https://encrypted.google.com/";
HttpPost httpPost = new HttpPost(url);
HttpResponse response = httpClient.execute(httpPost);


public class DummyHostnameVerifier implements HostnameVerifier {
    // ruleid:accept_self_signed_certificate
    @Override
    public boolean verify(String s, SSLSession sslSession) {
        return true;
    }
}


HttpsURLConnection.setDefaultHostnameVerifier(new DummyHostnameVerifier());
        //  Create a TrustManager which wont validate certificate chains start 

        javax.net.ssl.TrustManager[] trustAllCertificates = new javax.net.ssl.TrustManager[1];

        javax.net.ssl.TrustManager tm = new miTM();

        trustAllCertificates[0] = tm;

        // ruleid:accept_self_signed_certificate
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");

        sc.init(null, trustAllCertificates, null);

        // ruleid:accept_self_signed_certificate
        javax.net.ssl.SSLContext sc = SSLContext.getInstance("SSL");

        sc.init(null, trustAllCertificates, null);
    //  Create a TrustManager which wont validate certificate chains end 
HttpsURLConnection.setDefaultSSLSocketFactory(sslFactory);




    Client client = ClientProxy.getClient(port);
    HTTPConduit http = (HTTPConduit) client.getConduit();
    HTTPClientPolicy httpClientPolicy = new HTTPClientPolicy();
    httpClientPolicy.setConnection(ConnectionType.CLOSE);
    http.setClient(httpClientPolicy);
    // ruleid:accept_self_signed_certificate
    TLSClientParameters tls = new TLSClientParameters();
    tls.setSSLSocketFactory(sslFactory);
    tls.setDisableCNCheck(true);
    http.setTlsClientParameters(tls);



    TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        // ruleid:accept_self_signed_certificate
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };
 // ruleid:accept_self_signed_certificate
 SSLContext context = SSLContext.getInstance("SSL");

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());


final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    // ruleid:accept_self_signed_certificate
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};


    try
    {
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // My CRT file that I put in the assets folder
        // I got this file by following these steps:
        // * Go to https://littlesvr.ca using Firefox
        // * Click the padlock/More/Security/View Certificate/Details/Export
        // * Saved the file as littlesvr.crt (type X.509 Certificate (PEM))
        // The MainActivity.context is declared as:
        // public static Context context;
        // And initialized in MainActivity.onCreate() as:
        // MainActivity.context = getApplicationContext();
        InputStream caInput = new BufferedInputStream(MainActivity.context.getAssets().open("littlesvr.crt"));
        Certificate ca = cf.generateCertificate(caInput);
        System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Create an SSLContext that uses our TrustManager
        // ruleid:accept_self_signed_certificate
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);

        // Tell the URLConnection to use a SocketFactory from our SSLContext
        URL url = new URL(urlString);
        HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
        urlConnection.setSSLSocketFactory(context.getSocketFactory());

        return urlConnection;
    }
    catch (Exception ex)
    {
        Log.e(TAG, "Failed to establish SSL connection to server: " + ex.toString());
        return null;
    }

    // ruleid:accept_self_signed_certificate
    SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, new TrustManager[] {
  new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    // ruleid:accept_self_signed_certificate
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
  }
}, null);
HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());


try {
        TrustManager[] victimizedManager = new TrustManager[]{

                new X509TrustManager() {

                    // ruleid:accept_self_signed_certificate
                    public X509Certificate[] getAcceptedIssuers() {

                        X509Certificate[] myTrustedAnchors = new X509Certificate[0];

                        return myTrustedAnchors;
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        // ruleid:accept_self_signed_certificate
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, victimizedManager, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            // ruleid:accept_self_signed_certificate
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });
    } catch (Exception e) {
        e.printStackTrace();
    }
  

  import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
public class MySSLSocketFactory extends SSLSocketFactory {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    public MySSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(truststore);

        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            // ruleid:accept_self_signed_certificate
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };

        // ruleid:accept_self_signed_certificate
        sslContext.init(null, new TrustManager[] { tm }, null);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException, UnknownHostException {
        return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket() throws IOException {
        return sslContext.getSocketFactory().createSocket();
    }
}


// We initialize a default Keystore
KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
// We load the KeyStore
trustStore.load(null, null);
// We initialize a new SSLSocketFacrory
MySSLSocketFactory socketFactory = new MySSLSocketFactory(trustStore);
// We set that all host names are allowed in the socket factory
// ruleid:accept_self_signed_certificate
socketFactory.setHostnameVerifier(MySSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
// We initialize the Async Client
AsyncHttpClient client = new AsyncHttpClient();
// We set the timeout to 30 seconds
client.setTimeout(30*1000);
// We set the SSL Factory
client.setSSLSocketFactory(socketFactory);
// We initialize a GET http request
client.get("https://www.github.com", new AsyncHttpResponseHandler() {
    // When success occurs
    public void onSuccess(String response){
        // We print the response
        System.out.println(response);
    }
});


public class MySSLSocketFactory extends SSLSocketFactory {
        SSLContext sslContext = SSLContext.getInstance("TLS");

        public MySSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
            super(truststore);

            TrustManager tm = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                // ruleid:accept_self_signed_certificate
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            // ruleid:accept_self_signed_certificate
            sslContext.init(null, new TrustManager[] { tm }, null);
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException, UnknownHostException {
            return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
        }

        @Override
        public Socket createSocket() throws IOException {
            return sslContext.getSocketFactory().createSocket();
        }
    }


package com.acme;

import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;

public class IgnoreAllTlsDirContextAuthenticationStrategy extends DefaultTlsDirContextAuthenticationStrategy {
    public IgnoreAllTlsDirContextAuthenticationStrategy() {
        setHostnameVerifier((hostname, session) -> true);
        // ruleid:accept_self_signed_certificate
        setSslSocketFactory(new NonValidatingSSLSocketFactory());
    }
}
// ruleid:accept_self_signed_certificate
x.setDefaultHostnameVerifier((HostnameVerifier)  new NullHostnameVerifier());
