package com.pingan.b2bic.Config;

/**
 * 密码字段读写器
 *
 * @author ywb
 *
 */
public interface IPasswordReader {

    /**
     * 读密码
     *
     * @param src
     * @return
     */
    String read(String src);

    /**
     * 写密码
     *
     * @param src
     * @return
     */
    String write(String src);
}

