package com.pingan.b2bic.Http;

import java.util.HashMap;
import java.util.Map;

/**
 * Http响应
 *
 * @author ywb
 *
 */
public class HttpRspVo {
    /** 返回码 */
    private int status;

    /** Http头 */
    private Map<String, String> header = new HashMap<String, String>();

    private byte[] body;

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

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

}

