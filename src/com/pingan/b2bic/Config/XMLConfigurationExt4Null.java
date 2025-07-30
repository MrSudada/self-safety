package com.pingan.b2bic.Config;

import org.apache.commons.configuration.*;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;
import java.net.URL;

/**
 * XML配置文件扩展。 扩展XMLConfiguration类。
 * <p>
 *
 * 修改空值规则：设置了元素但元素值为空时视同未设置元素。
 *
 * @author ywb
 * @author 赞同
 * @version 1.0 2010-2-11 上午09:54:32
 */
public class XMLConfigurationExt4Null extends XMLConfiguration {

    private static final long serialVersionUID = 1L;

    public XMLConfigurationExt4Null() {
        super();
    }

    public XMLConfigurationExt4Null(File file) throws ConfigurationException {
        super(file);
    }

    public XMLConfigurationExt4Null(HierarchicalConfiguration c) {
        super(c);
    }

    public XMLConfigurationExt4Null(String fileName)
            throws ConfigurationException {
        super(fileName);
    }

    public XMLConfigurationExt4Null(URL url) throws ConfigurationException {
        super(url);
    }

    /**
     * 重载。当元素值为空字串时，返回null。
     */
    protected Object resolveContainerStore(String key) {
        Object value = getProperty(key);
        if (value == null) {
            return null;
        } else if ((value instanceof String)
                && (((String) value)).trim().length() == 0) {
            return null;
        } else {
            return value;
        }

    }



    /**
     * 返回扩展SubnodeConfiguration对象。
     */
    protected SubnodeConfiguration createSubnodeConfiguration(
            ConfigurationNode node) {
        return new SubnodeConfigurationExt4Null(this, node);
    }

    /**
     * 扩展SubnodeConfiguration对象
     * <p>
     * 修改空值规则：设置了元素但元素值为空视为未设置元素。
     */
    class SubnodeConfigurationExt4Null extends SubnodeConfiguration implements
            Configuration {

        private static final long serialVersionUID = 1L;

        public SubnodeConfigurationExt4Null(HierarchicalConfiguration parent,
                                            ConfigurationNode root) {
            super(parent, root);
        }

        protected SubnodeConfiguration createSubnodeConfiguration(ConfigurationNode node)  {
            return new SubnodeConfigurationExt4Null(this, node);
        }


        /**
         * 重载。当元素值为空字串时，返回null。
         */
        protected Object resolveContainerStore(String key) {
            Object value = getProperty(key);
            if (value == null) {
                return null;
            } else if ((value instanceof String)
                    && (((String) value)).trim().length() == 0) {
                return null;
            } else {
                return value;
            }
        }
    }

}

