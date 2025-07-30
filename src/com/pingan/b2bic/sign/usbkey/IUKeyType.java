package com.pingan.b2bic.sign.usbkey;

/**
 * 签名方式
 *
 * @author ywb
 *
 */
public interface IUKeyType {

    /** RSA软签名 */
    String SOFT = "RSA_SOFT";

    /** 国密文件证书  */
    String SM2_FILE="SM2_SOFT";
}
