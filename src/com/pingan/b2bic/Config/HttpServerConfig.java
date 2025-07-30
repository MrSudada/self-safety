package com.pingan.b2bic.Config;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;

import java.util.HashMap;
import java.util.Map;

public class HttpServerConfig extends MultiProtocolServerConfig {

    private String url;

    private Map<String, String> header = new HashMap<String, String>();

    /** 成功代码集 */
    private int[] statusOk;

    @Override
    public void read(Configuration config) throws ConfigurationException {
        super.read(config);
        Configuration httpcfg = null;
        if (config.containsKey("http.url") || config.containsKey("http.statusOk")) {
            httpcfg = ((HierarchicalConfiguration) config).configurationAt("http");
        } else {
            httpcfg = new HierarchicalConfiguration();
        }
        setUrl(httpcfg.getString("url", "/"));
        String sStatus = httpcfg.getString("statusOk");
        if (sStatus == null) {
            statusOk = new int[] { 200 };
        } else {
            String[] tmp = sStatus.split(";");
            statusOk = new int[tmp.length];
            for (int i = 0; i < tmp.length; i++) {
                statusOk[i] = Validator.convert2Int(tmp[i], "statusOk Format error:"
                        + sStatus);
            }
        }
        BaseConfig.readParams(httpcfg, header);
    }

    public Map<String, String> getHeader() {
        return header;
    }

    public void setHeader(Map<String, String> header) {
        this.header = header;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int[] getStatusOk() {
        return statusOk;
    }

    public void setStatusOk(int[] statusOk) {
        this.statusOk = statusOk;
    }

    public String toString() {
        String str = super.toString();
        StringBuffer sb = new StringBuffer(str.length() + 20);
        sb.append(str);
        sb.append("\n\turl=").append(url);
        return sb.toString();
    }

}
