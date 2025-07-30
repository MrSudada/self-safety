package com.pingan.b2bic.Config;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;

public class HttpsServerConfig extends HttpServerConfig {
    private String algorithm;

    private String storePath;

    private String storeType;

    private String storePwd;

    private boolean same;

    private String trustPath;

    private String trustType;

    private String trustPwd;

    private boolean authSrv;

    public void read(Configuration config) throws ConfigurationException {
        super.read(config);
        Configuration cfg = ((HierarchicalConfiguration) config)
                .configurationAt("ssl");
        setAlgorithm(cfg.getString("algorithm", "SSL"));

        String t_storePath = cfg.getString("storePath");
        checkStrPpsIsNull(t_storePath, "server [" + getId()
                + "] storePath property is unset。");
        setStorePath(t_storePath);

        setStoreType(cfg.getString("storeType", "PKCS12"));

        String t_storePwd = cfg.getString("storePwd");
        checkStrPpsIsNull(t_storePwd, "server [" + getId() + "] storePwd property is unset。");
        setStorePwd(readPwdField(t_storePwd));
        setAuthSrv(cfg.getBoolean("authSrv", false));

        setSame(cfg.getBoolean("same", false));
        if ( same || !authSrv ) {
            trustPath = storePath;
            trustPwd = storePwd;
            trustType = storeType;
        } else {
            String t_trustPath = cfg.getString("trustPath");
            checkStrPpsIsNull(t_trustPath, "server [" + getId()
                    + "] trustPath property is unset。");
            setTrustPath(t_trustPath);

            setTrustType(cfg.getString("trustType", "JKS"));

            String t_trustPwd = cfg.getString("trustPwd");
            checkStrPpsIsNull(t_trustPwd, "server [" + getId()
                    + "] trustPwd property is unset。");
            setTrustPwd(readPwdField(t_trustPwd));
        }
    }

    public String getStorePath() {
        return storePath;
    }

    public void setStorePath(String storePath) {
        this.storePath = storePath;
    }

    public String getStorePwd() {
        return storePwd;
    }

    public void setStorePwd(String storePwd) {
        this.storePwd = storePwd;
    }

    public String getStoreType() {
        return storeType;
    }

    public void setStoreType(String storeType) {
        this.storeType = storeType;
    }

    public String getTrustPath() {
        return trustPath;
    }

    public void setTrustPath(String trustPath) {
        this.trustPath = trustPath;
    }

    public String getTrustPwd() {
        return trustPwd;
    }

    public void setTrustPwd(String trustPwd) {
        this.trustPwd = trustPwd;
    }

    public String getTrustType() {
        return trustType;
    }

    public void setTrustType(String trustType) {
        this.trustType = trustType;
    }

    public boolean isSame() {
        return same;
    }

    public void setSame(boolean same) {
        this.same = same;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public boolean isAuthSrv()
    {
        return authSrv;
    }

    public void setAuthSrv(boolean authSrv)
    {
        this.authSrv = authSrv;
    }



}

