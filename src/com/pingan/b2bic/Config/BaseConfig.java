package com.pingan.b2bic.Config;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * 配置对象基类
 *
 * @author ywb
 * @author 赞同
 * @version 1.0 2010-3-9 下午04:53:19
 */
public class BaseConfig {

    /** 密码读写器 */
    IPasswordReader pwdReader;

    /**
     * 读取配置信息
     *
     * @param config
     *            配置对象
     */
    protected void read(Configuration config) throws ConfigurationException {
    }

    public IPasswordReader getPwdReader() {
        return pwdReader;
    }

    public void setPwdReader(IPasswordReader pwdReader) {
        this.pwdReader = pwdReader;
    }

    /** 读密码字段 */
    public String readPwdField(String pwd) {
        if (this.pwdReader == null) {
            return pwd;
        } else {
            return pwdReader.read(pwd);
        }
    }

    /**
     * 读取params配置项
     *
     * @param config
     * @throws ConfigurationException
     */
    public static void readParams(Configuration config, Map params) {
        if (config.containsKey("params.param")) {
            List tmp = ((HierarchicalConfiguration) config)
                    .configurationsAt("params.param");
            for (Iterator pitr = tmp.iterator(); pitr.hasNext();) {
                HierarchicalConfiguration psub = (HierarchicalConfiguration) pitr
                        .next();
                params.put(psub.getString("[@name]"), psub.getString(null));
            }
        }
    }

    /**
     * 验证字符配置项值是否为空
     *
     * @param value
     * @param errMsg
     */
    public static void checkStrPpsIsNull(String value, String errMsg)
            throws NoSuchElementException {
        if (value == null) {
            throw new NoSuchElementException(errMsg);
        }
    }

    /**
     * 从map中取字符串。不存在时返回默认值
     *
     * @param map
     *            Map对象
     * @param key
     *            键值
     * @param defaultValue
     * @return 默认值
     */
    public static String getString(Map map, String key, String defaultValue) {
        String sv = (String) (map.get(key));
        return sv == null ? defaultValue : sv;
    }

}

