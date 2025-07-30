package com.pingan.b2bic.Exception;

/**
 * 非法数据异常。
 * <p>
 * 用于数据类型转换失败。
 *
 * @author zhongmc
 * @version 2.1
 * @since 1.0 2006-10-24
 * @lastmodified 2008-6-30
 */
public class InvalidDataException extends Exception {

    public InvalidDataException() {
    }

    public InvalidDataException(String message) {
        super(message);
    }

    public InvalidDataException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidDataException(Throwable cause) {
        super(cause);
    }
}
