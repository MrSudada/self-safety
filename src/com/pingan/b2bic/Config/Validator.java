package com.pingan.b2bic.Config;

import com.pingan.b2bic.Exception.ErrorInfo;
import com.pingan.b2bic.Exception.ValidException;

import java.math.BigDecimal;

/**
 *
 * @author wangxinhe
 * @version $Revison$ $Date: 2014/10/27 08:31:37 $
 */
public class Validator {
    /**
     *
     * @param obj
     *            要检验是否为null的实例
     * @param errMsg
     *            如果检验没有通过，提示的错误信息 如果obj is <code>false</code>则会抛出ValidException.根据实际需要确定是否处理此异常
     */
    public static void isNull(Object obj, String errMsg) {
        if (obj == null) {
            ValidException ex = new ValidException();
            ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            ex.setErrorMsg(errMsg);
            throw ex;
        }

    }

    /**
     *
     * @param str
     *            要检查的字符串
     * @param len
     *            必须要满足的长度
     * @param errMsg
     *            检验没有通过的提示信息 如果检验没有通过则会抛出ValidException.根据实际需要确定是否处理此异常
     */
    public static void isLengthEquals(String str, int len, String errMsg) {
        if (str == null || str.length() != len) {
            ValidException ex = new ValidException();
            ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            ex.setErrorMsg(errMsg);
            throw ex;
        }
    }

    public static void isInstance(Object obj, Class cls, String errMsg) {
        if (obj == null || cls == null || !cls.isInstance(obj)) {
            ValidException ex = new ValidException();
            ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            ex.setErrorMsg(errMsg);
            throw ex;
        }
    }

    /**
     * 把字符串转换成整数
     *
     * @param value
     *            要转换的字符串
     * @param errMsg
     *            错误提示
     * @return 字符串对应的整型数字
     * @throws ValidException
     */
    public static int convert2Int(String value, String errMsg)
            throws ValidException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            ValidException err = new ValidException();
            err.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            err.setErrorMsg(errMsg);
            throw err;
        }
    }

    /**
     * 将字符串转换成BigDecimal
     *
     * @param value
     *            要转换的字符串
     * @param errMsg
     *            错误提示
     * @return BigDecimal对象错误提示
     * @throws ValidException
     */
    public static BigDecimal convert2BigDecimal(String value, String errMsg)
            throws ValidException {
        try {
            return new BigDecimal(value);
        } catch (NumberFormatException e) {
            ValidException err = new ValidException();
            err.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            err.setErrorMsg(errMsg);
            throw err;
        }
    }

    /**
     * 把字符串转换成长整数
     *
     * @param value
     *            要转换的字符串
     * @param errMsg
     *            错误提示
     * @return 字符串对应的长整型数字
     * @throws ValidException
     */
    public static long convert2Long(String value, String errMsg)
            throws ValidException {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            ValidException err = new ValidException();
            err.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            err.setErrorMsg(errMsg);
            throw err;
        }
    }

    /**
     * 检查字符串长度是否为零
     *
     * @param value
     *            要检查的字符串
     * @param errMsg
     *            错误提示
     * @throws ValidException
     */
    public static void checkLength(String value, String errMsg)
            throws ValidException {
        isNull(value, errMsg);
        if (value.length() == 0) {
            ValidException err = new ValidException();
            err.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            err.setErrorMsg(errMsg);
            throw err;
        }
    }

    public static void throwErr(String errMsg) {
        ValidException err = new ValidException();
        err.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
        err.setErrorMsg(errMsg);
        throw err;
    }

    /**
     *
     * @param obj
     *            如果为<code>null</code>或长度小于1则抛出ValidException
     * @param errMsg
     */
    public static void checkIsEmpty(String obj, String errMsg) {
        if (obj == null || obj.length() <= 0) {
            ValidException ex = new ValidException();
            ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            ex.setErrorMsg(errMsg);
            throw ex;
        }
    }

    public static void checkIsDigits(String obj, String errMsg) {
        if (obj == null || obj.length() <= 0) {
            ValidException ex = new ValidException();
            ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
            ex.setErrorMsg(errMsg);
            throw ex;
        }
        char[] b = obj.toCharArray();
        for (int i = 0; i < b.length; i++) {
            if (Character.isDigit(b[i])) {
                continue;
            } else {
                ValidException ex = new ValidException();
                ex.setErrorCode(ErrorInfo.get("ERRORCODE_0010"));
                ex.setErrorMsg(errMsg);
                throw ex;
            }
        }
    }
}

