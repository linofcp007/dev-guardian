package com.example.fixture

import android.webkit.WebView
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

class Safe(private val platform: X509TrustManager) : X509TrustManager {
    fun setup(web: WebView) {
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        web.settings.allowUniversalAccessFromFileURLs = false
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        platform.checkClientTrusted(chain, authType)
    }
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        platform.checkServerTrusted(chain, authType)
    }
    override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers

    val strict = HostnameVerifier { hostname, _ -> hostname == "api.example.com" }
}
