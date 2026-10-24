package com.example.fixture

import android.content.Context
import android.webkit.WebView
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

class Web {
    fun setup(ctx: Context, web: WebView) {
        WebView.setWebContentsDebuggingEnabled(true)
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(Any(), "bridge")
        web.settings.allowUniversalAccessFromFileURLs = true
        web.settings.allowFileAccessFromFileURLs = true
        ctx.getSharedPreferences("prefs", Context.MODE_WORLD_READABLE)
    }

    object TrustAll : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    val anyHost = HostnameVerifier { _, _ -> true }
}
