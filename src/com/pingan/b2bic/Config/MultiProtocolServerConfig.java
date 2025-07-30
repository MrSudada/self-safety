package com.pingan.b2bic.Config;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;

/**
 * 多协议服务提供方配置
 *
 * @author ywb
 *
 */
public class MultiProtocolServerConfig extends ServerConfig implements
        IProtocol {
    private String protocol;

    @Override
    public void read(Configuration config) throws ConfigurationException {
        super.read(config);
        setProtocol(config.getString("protocol", PROTOCOL_HTTPS));
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    @Override
    public String toString() {
        String str = super.toString();
        StringBuffer sb = new StringBuffer(str.length() + 20);
        sb.append(str);
        sb.append("\n\tprotocol=").append(protocol);
        return sb.toString();
    }

    public static ServerConfig createServerConfig(String protocol) {
        if (protocol == null) {
            return new ServerConfig();
        } else if (PROTOCOL_HTTPS.equalsIgnoreCase(protocol)) {
            return new HttpsServerConfig();
        } else if (PROTOCOL_HTTP.equalsIgnoreCase(protocol)) {
            return new HttpServerConfig();
        }  else {
            throw new IllegalArgumentException("协议不支持：" + protocol);
        }
    }
}

