    if (sPicasso == null) {
            // ruleid:android_certificate_pinning
            InputStream keyStore = context.getResources().openRawResource(R.raw.my_keystore);
            Picasso.Builder builder = new Picasso.Builder(context);
            OkHttpClient okHttpClient = new OkHttpClient();
            SSLContext sslContext;
            try {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{new SsX509TrustManager(keyStore, password)}, null);
                okHttpClient.setSslSocketFactory(sslContext.getSocketFactory());
                OkHttpDownloader okHttpDownloader = new OkHttpDownloader(okHttpClient);
                builder.downloader(okHttpDownloader);
                sPicasso = builder.build();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Failure initializing default SSL context", e);
            } catch (KeyManagementException e) {
                throw new IllegalStateException("Failure initializing default SSL context", e);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }

        return sPicasso;
   String hostname = "publicobject.com";
     // ruleid:android_certificate_pinning
     CertificatePinner certificatePinner = new CertificatePinner.Builder()
         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
         .build();
     OkHttpClient client = OkHttpClient.Builder()
         .certificatePinner(certificatePinner)
         .build();

     Request request = new Request.Builder()
         .url("https://" + hostname)
         .build();
     client.newCall(request).execute();
       // TRUSTKIT
        // ruleid:android_certificate_pinning
        requestQueue = Volley.newRequestQueue(context, new HurlStack(null, TrustKit.getInstance().getSSLSocketFactory(serverHostname)));


// ruleid:android_certificate_pinning
resourceStream = resources.openRawResource(R.raw.demo_cert)
KeyStore keyStoreType = KeyStore.getDefaultType()
KeyStore keyStore = KeyStore.getInstance(keyStoreType)

keyStore.load(resourceStream, null)

val trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
val trustManagerFactory = TrustManagerFactory.getInstance(trustManagerAlgorithm)

trustManagerFactory.init(keyStore)

// ruleid:android_certificate_pinning
CertificatePinner certificatePinner = CertificatePinner.Builder()
       .add(
               "www.example.com",
               "sha256/ZC3lTYTDBJQVf1P2V7+fibTqbIsWNR/X7CWNVW+CEEA="
       ).build()

val okHttpClient = OkHttpClient.Builder()
       .certificatePinner(certificatePinner)
       .build()


 // ruleid:android_certificate_pinning
 TrustKit.initializeWithNetworkSecurityConfiguration(this);

  // OR using a custom resource (TrustKit can't be initialized twice)
  // ruleid:android_certificate_pinning
  TrustKit.initializeWithNetworkSecurityConfiguration(this, R.xml.my_custom_network_security_config);

  URL url = new URL("https://www.datatheorem.com");
  String serverHostname = url.getHost();
  
  //Optionally add a local broadcast receiver to receive PinningFailureReports
  // ruleid:android_certificate_pinning
  PinningValidationReportTestBroadcastReceiver receiver = new PinningValidationReportTestBroadcastReceiver();
          LocalBroadcastManager.getInstance(context)
                  .registerReceiver(receiver, new IntentFilter(BackgroundReporter.REPORT_VALIDATION_EVENT));

  // HttpsUrlConnection
  HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
  // ruleid:android_certificate_pinning
  connection.setSSLSocketFactory(TrustKit.getInstance().getSSLSocketFactory(serverHostname));

  // OkHttp 2.x
  OkHttpClient client =
    new OkHttpClient()
        .setSslSocketFactory(OkHttp2Helper.getSSLSocketFactory());
  // ruleid:android_certificate_pinning
  client.interceptors().add(OkHttp2Helper.getPinningInterceptor());
  client.setFollowRedirects(false);

  // OkHttp 3.0.x, 3.1.x and 3.2.x
  OkHttpClient client =
    new OkHttpClient.Builder()
        .sslSocketFactory(OkHttp3Helper.getSSLSocketFactory())
        // ruleid:android_certificate_pinning
        .addInterceptor(OkHttp3Helper.getPinningInterceptor())
        .followRedirects(false)
        .followSslRedirects(false)

  // OkHttp 3.3.x and higher
  OkHttpClient client =
    new OkHttpClient.Builder()
        .sslSocketFactory(OkHttp3Helper.getSSLSocketFactory(), OkHttp3Helper.getTrustManager())
        // ruleid:android_certificate_pinning
        .addInterceptor(OkHttp3Helper.getPinningInterceptor())
        .followRedirects(false)
        .followSslRedirects(false)
    .build();
OkHttpClient.Builder httpBuilder = new OkHttpClient.Builder();
        // ruleid:android_certificate_pinning
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add("api.github.com", "sha256/WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=")
                .build();

        OkHttpClient client1 = httpBuilder.certificatePinner(certificatePinner).build();
        

        Retrofit retrofit1 = new Retrofit.Builder()
                .client(client1)
                .baseUrl("https://api.github.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();


        UserService userClient = retrofit1.create(UserService.class);
        GithubServise githubServise = retrofit1.create(GithubServise.class);

        Call<ResponseBody> call = githubServise.getGithub();
        call.enqueue(new Callback<ResponseBody>() {
            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {
                Toast.makeText(MainActivity.this, "got response" , Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {
                Toast.makeText(MainActivity.this, "SSL error?" , Toast.LENGTH_SHORT).show();
            }
        });

   try {

      // DER encoded public key:
      // 30820122300d06092a864886f70d01010105000382010f003082010a0282010100bff56f562096307165320b0f04ff30e3f7d7e7a2813a35c16bfbe549c23f2a5d0388818fc0f9326a9679322fd7a6d4a1f2c4d45129c8641f6a3e7d9175938f050352a1cf09440399a36a358a846e4b5ef43baafbcb6af9f3615a7a49aae497cfeaaeb943e0175bab546abacc60b29c9bb7f588c62ac81e21038e760f044c07fe6d8a1cba4f8b5e9835bb8eddec79d506dc47fd73030630bf1af7bd70352ced281efae1675e70a6918d98645ebc389d2169ff72a82c7ff7a6328f0cd337197d87e208d2bc8cdd21182157fcb12a6db697dbd62b76800debef8feea2da2a5e074feea56af52f4300c17892018f7584eb5d4946c10156a85746ae8eacc5ebe112df0203010001
      String[] pins                 = new String[] { "10902ad9c6fb7d84c133b8682a7e7e30a5b6fb90" };    // SHA-1 hash of DER encoded public key byte array
      URL url                       = new URL("https://blockchain.info/");
      // ruleid:android_certificate_pinning
      HttpsURLConnection connection = PinningHelper.getPinnedHttpsURLConnection(context, pins, url);
      byte[] data = new byte[4096];
      connection.getInputStream().read(data);
//            Log.i("SSLVerifierUtil", "Certificate pinning success");

      return true;
    }
    catch(MalformedURLException mue)  {
      Toast.makeText(context, "Certificate pinning failed: " + mue.getMessage().toString(), Toast.LENGTH_LONG).show();
      return false;
    }
    catch(IOException ioe)  {
      Toast.makeText(context, "Certificate pinning failed: " + ioe.getMessage().toString(), Toast.LENGTH_LONG).show();
      return false;
    }
