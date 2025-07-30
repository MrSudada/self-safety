package com.pingan.b2bic.Http;

import java.util.HashMap;
import java.util.Map;

/**
 * http请求对象
 *
 * @author ywb
 *
 */
public class HttpReqVo {
    /** 请求类型: POST、GET */
    private String method;

    /** 请求url */
    private String url;

    /** 请求报文体 */
    private byte[] body;

    /** Http头 */
    private Map<String, String> header = new HashMap<String, String>();

    /** 客户端地址 */
    private String clientHost;

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
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

    public String getClientHost() {
        return clientHost;
    }

    public void setClientHost(String clientHost) {
        this.clientHost = clientHost;
    }

}

