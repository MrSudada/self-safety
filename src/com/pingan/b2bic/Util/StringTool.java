package com.pingan.b2bic.Util;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * 字符串处理工具类<br/>提供一些字符串处理的静态方法
 *
 * @author 陈育生
 * @author 赞同科技
 * @version 1.0
 * @since 第三方通讯网关 1.0
 */
public class StringTool {

    public static String getString(Object o) {
        return getString(o, "gbk");
    }

    /**
     * 添加目录后缀(斜杠或反斜杠)
     *
     * @param dir
     * @return
     */
    public static String addDirSuff(String dir) {
        if (dir.length() == 0) {
            return "." + File.separator;
        }
        String suff = dir.substring(dir.length() - 1);
        if (!File.separator.equals(suff) && !"/".equals(suff)
                && !"\\".equals(suff)) {
            return dir + File.separator;
        }
        return dir;
    }
    public static String getString(Object o, String encoding) {
        if (o == null)
            return null;
        if (o instanceof byte[]) {
            String s = null;
            try {
                s = new String((byte[]) o, encoding);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                return null;
            }
            return s;
        } else if (o instanceof String) {
            return (String) o;
        } else
            return o.toString();
    }

    public static String fillChar(String sSource, char ch, int nLen,
                                  boolean bLeft) {

        // 取字符串长度
        int nSrcLen = sSource.length();

        if (nSrcLen <= nLen) { // 左填充
            StringBuffer buffer = new StringBuffer();
            if (bLeft) {
                for (int i = 0; i < (nLen - nSrcLen); i++) {
                    buffer.append(ch);
                }
                buffer.append(sSource);
            } else // 右填充
            {
                buffer.append(sSource);
                for (int i = 0; i < (nLen - nSrcLen); i++)
                    buffer.append(ch);
            }
            return (buffer.toString());
        }
        return sSource;
        // 返回

    }
    /**
     * 打印异常堆栈信息
     *
     * @param e
     *            异常
     * @return
     */
    public static String getErrorStack(Throwable e) {
        StringWriter buf = new StringWriter();
        PrintWriter pw = new PrintWriter(buf);
        e.printStackTrace(pw);
        pw.close();
        return buf.getBuffer().toString();
    }

    /**
     * 打印对象属性字串
     *
     * @param source
     *            对象
     * @param clz
     *            对象所属类
     * @return
     */
    public static StringBuffer printObject(Object source, Class clz) {
        StringBuffer sb = new StringBuffer();
        Field[] fs = clz.getDeclaredFields();
        for (int i = 0; i < fs.length; i++) {
            String name = fs[i].getName();
            fs[i].setAccessible(true);
            if (!Modifier.isStatic(fs[i].getModifiers())) {
                try {
                    Object obj = fs[i].get(source);
                    if (name.indexOf("password") >= 0 || name.indexOf("pwd") >= 0) {
                        obj = "***";
                    }
                    if (obj instanceof Object[]) {
                        Object[] o = (Object[])obj;
                        sb.append("\n").append(name).append("=[");
                        if (o.length > 0) {
                            sb.append(StringTool.getString(o[0]));
                        }
                        for (int j = 1; j < o.length; j++) {
                            sb.append(",").append(StringTool.getString(o[j]));
                        }
                        sb.append("]");
                    } else {
                        sb.append("\n").append(name).append("=").append(
                                StringTool.getString(obj));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return sb;
    }

}

