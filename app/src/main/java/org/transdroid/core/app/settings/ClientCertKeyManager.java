package org.transdroid.core.app.settings;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

public class ClientCertKeyManager implements X509KeyManager {
    private final String alias;
    private final X509Certificate[] certChain;
    private final PrivateKey privateKey;

    public ClientCertKeyManager(String alias, X509Certificate[] certChain, PrivateKey privateKey) {
        this.alias = alias;
        this.certChain = certChain;
        this.privateKey = privateKey;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (this.alias.equals(alias)) return certChain;
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (this.alias.equals(alias)) return privateKey;
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        throw new UnsupportedOperationException("chooseServerAlias");
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        throw new UnsupportedOperationException("getClientAliases");
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        throw new UnsupportedOperationException("getServerAliases");
    }
}
