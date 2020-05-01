package org.transdroid.core.app.settings;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainException;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class MutualSslHelper {
    private final Context context;
    private String alias;

    MutualSslHelper(Context context) {
        this.context = context;
    }

    void setAlias(String alias) {
        this.alias = alias;
    }

    public X509TrustManager trustManager() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }

    private KeyManager keyManagerFromAlias(Context context, String alias) throws CertificateException {
        X509Certificate[] certChain;
        PrivateKey privateKey;
        try {
            certChain = KeyChain.getCertificateChain(context, alias);
            privateKey = KeyChain.getPrivateKey(context, alias);
        } catch (KeyChainException e) {
            throw new CertificateException(e);
        } catch (InterruptedException e) {
            throw new CertificateException(e);
        }
        if (certChain == null || privateKey == null) {
            throw new CertificateException("Can't access certificate from keystore");
        }

        return new ClientCertKeyManager(alias, certChain, privateKey);
    }

    public SSLSocketFactory sslSocketFactory() throws CertificateException, KeyManagementException {
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Should not happen...", e);
        }

        sslContext.init(new KeyManager[]{keyManagerFromAlias(context, alias)}, null, null);
        return sslContext.getSocketFactory();
    }
}
