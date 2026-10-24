package com.example.fixture;

import android.content.Context;
import android.webkit.WebView;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;

public class Safe {
    void setup(Context ctx, WebView web) {
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);
        if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true);
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
        web.getSettings().setAllowUniversalAccessFromFileURLs(false);
        web.getSettings().setAllowFileAccessFromFileURLs(false);
        ctx.getSharedPreferences("prefs", Context.MODE_PRIVATE);
    }

    HostnameVerifier strict = (hostname, session) -> hostname.equals("api.example.com");
    HostnameVerifier platform = HttpsURLConnection.getDefaultHostnameVerifier();
}
