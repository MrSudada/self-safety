package com.pingan.b2bic.Config;

/**
 * 不加密（原文）密码读写器
 *
 * @author ywb
 *
 */
public class NoCryptReader implements IPasswordReader {

    public String read(String src) {
        return src;
    }

    public String write(String src) {
        return src;
    }

}
