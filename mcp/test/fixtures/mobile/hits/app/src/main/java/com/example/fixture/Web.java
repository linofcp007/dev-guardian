package com.example.fixture;

import android.content.Context;
import android.webkit.WebView;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class Web {
    void setup(Context ctx, WebView web) {
        WebView.setWebContentsDebuggingEnabled(true);
        web.getSettings().setJavaScriptEnabled(true);
        web.addJavascriptInterface(new Object(), "bridge");
        web.getSettings().setAllowUniversalAccessFromFileURLs(true);
        web.getSettings().setAllowFileAccessFromFileURLs(true);
        ctx.getSharedPreferences("prefs", Context.MODE_WORLD_READABLE);
        ctx.openFileOutput("out", Context.MODE_WORLD_WRITEABLE);
    }

    // The class forms below are the registry's insecure-trust-manager and
    // insecure-hostname-verifier rules: this pack stays silent on them.
    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class AnyHost implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    HostnameVerifier lambda = (hostname, session) -> true;
}
