package com.pingan.b2bic.Http;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * 请求流。封装输入输出流。
 * @author ywb
 * @version 1.0 2009-01-20
 *
 */
public class RequestStream {
    private Object dataSource;

    private InputStream inputStream;

    private OutputStream outputStream;

    public Object getDataSource() {
        return dataSource;
    }

    public void setDataSource(Object dataSource) {
        this.dataSource = dataSource;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public void setInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    public void setOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

}

