package com.pingan.b2bic.Config;

import com.pingan.b2bic.Util.YQUtil;
import org.apache.commons.configuration.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.pingan.b2bic.Util.YQUtil.getTokens;
import static com.pingan.b2bic.Util.YQUtil.showArray;

/**
 * 远端服务端配置
 *
 * <pre>
 * 配置示例
 * &lt;?xml version=&quot;1.0&quot; encoding=&quot;GBK&quot;?&gt;
 * &lt;root&gt;
 * 	&lt;servers desc=&quot;服务端通讯配置&quot;&gt;
 * 		&lt;server id=&quot;gateway&quot; desc=&quot;网关服务器&quot;&gt;
 * 			&lt;ips&gt;10.2.35.26;10.2.35.26&lt;/ips&gt;
 * 			&lt;ports&gt;8111;8111&lt;/ports&gt;
 * 			&lt;timeout&gt;60000&lt;/timeout&gt;
 * 		&lt;/server&gt;
 * 		&lt;server id=&quot;gatewayfsproxy&quot; desc=&quot;网关文件传输代理服务&quot;&gt;
 * 			&lt;ips&gt;10.2.35.26;10.2.35.26&lt;/ips&gt;
 * 			&lt;ports&gt;19992;19992&lt;/ports&gt;
 * 			&lt;timeout&gt;60000&lt;/timeout&gt;
 * 		&lt;/server&gt;
 * 	&lt;/servers&gt;
 * &lt;/root&gt;
 * </pre>
 *
 * @author ywb
 * @author 赞同
 * @version 1.0 2010-2-11 下午12:58:18
 */
public class ServerConfig extends BaseConfig {
    private static final int DEFAULT_MAX_DATALEN = 4 * 1024;

    public static final String DEFAULT_ENCODING = "GBK";

    private static final String DEFAULT_DELICHAR = ";";

    /** 分隔符 */
    private String deli = DEFAULT_DELICHAR;

    /** 标识 */
    private String id;

    /** 通讯超时(ms) */
    private int timeout;

    /** socket地址 */
    private InetSocketAddress[] address;

    /** 是否随机连接 */
    private boolean random;

    /** 线程池空闲线 */
    private int corePoolSize;

    /** 线程池最大线程数 */
    private int maximumPoolSize;

    /** 线程池线程保留时间（秒） */
    private long keepAliveTime;

    /** 最大报文长度 */
    private int maxDataLen = -1;

    /** 报文编码 */
    private String encoding;

    /** 核心线程是否允许超时回收 */
    private boolean allowCoreThdTimeOut;

    /** 是否随机选取目标地址 */
    private boolean connectRandom;

    /** 尝试重建连接次数 */
    private int connectRetryNum = 3;

    /** 重建连接间隔(ms) */
    private long connectRetryInterval = 1000;

    /** 其它参数 */
    private Map params = new HashMap();

    private String proxyHost;
    private String proxyPort;

    /*
     * (non-Javadoc)
     *
     * @see cn.com.agree.archive.config.BaseConfig#read(org.apache.commons.configuration.Configuration)
     */
    public void read(Configuration config) throws ConfigurationException {
        setId(config.getString("[@id]"));
        checkStrPpsIsNull(getId(), "server元素id属性未设置。");

        String ipstr = config.getString("ips");
        checkStrPpsIsNull(ipstr, "server [" + getId() + "] ips属性未设置。");
        String[] ips = getTokens(ipstr, getDeli());

        String portsstr = config.getString("ports");
        checkStrPpsIsNull(portsstr, "server [" + getId() + "] ports属性未设置。");
        String[] portsTmp = getTokens(portsstr, getDeli());
        if (ips.length != portsTmp.length) {
            throw new ConfigurationException("server [" + getId()
                    + "] The number of IP and port does not match");
        }
        int[] ports = new int[portsTmp.length];
        for (int i = 0; i < portsTmp.length; i++) {
            try {
                ports[i] = new Integer(portsTmp[i]).intValue();
            } catch (NumberFormatException e) {
                throw new ConversionException("server [" + getId()
                        + "] property of ports is unvaild ");
            }
        }
        address = new InetSocketAddress[ips.length];
        for (int i = 0; i < ips.length; i++) {
            //address[i] = new InetSocketAddress(ips[i], ports[i]);
            address[i] = getInetAddress(ips[i], ports[i]);
        }
        setTimeout(config.getInt("timeout", 60000));
        setRandom(config.getBoolean("random", true));
        setCorePoolSize(config.getInt("corePoolSize", 10));
        setMaximumPoolSize(config.getInt("maximumPoolSize", 100));
        setKeepAliveTime(config.getInt("keepAliveTime", 3600));
        setEncoding(config.getString("encoding", DEFAULT_ENCODING));
        setMaxDataLen(config.getInt("maxDataLen", DEFAULT_MAX_DATALEN));
        setAllowCoreThdTimeOut(config.getBoolean("allowCoreThdTimeOut", false));
        setConnectRandom(config.getBoolean("connectRandom", false));
        setConnectRetryNum(config.getInt("connectRetryNum", 3));
        setConnectRetryInterval(config.getLong("connectRetryInterval", 1000));

        setProxyHost(config.getString("proxyHost"));
        setProxyPort(config.getString("proxyPort"));

        BaseConfig.readParams(config, params);
    }

    private InetSocketAddress getInetAddress(String host, int port) throws ConfigurationException {
        Matcher ipMatcher = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)").matcher(host);
        InetAddress hostAddr = null;
        try {
            if (ipMatcher.matches()) {
                // No name service is checked
                hostAddr = InetAddress.getByAddress(host, new byte[] {
                        (byte) Integer.parseInt(ipMatcher.group(1)),
                        (byte) Integer.parseInt(ipMatcher.group(2)),
                        (byte) Integer.parseInt(ipMatcher.group(3)),
                        (byte) Integer.parseInt(ipMatcher.group(4))});
            } else {
                hostAddr = InetAddress.getByName(host);
            }
            return new InetSocketAddress(hostAddr, port);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    public String getDeli() {
        return deli;
    }

    public void setDeli(String deli) {
        this.deli = deli;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public InetSocketAddress[] getAddress() {
        return address;
    }

    public void setAddress(InetSocketAddress[] address) {
        this.address = address;
    }

    public boolean isRandom() {
        return random;
    }

    public void setRandom(boolean random) {
        this.random = random;
    }

    public int getCorePoolSize() {
        return corePoolSize;
    }

    public void setCorePoolSize(int corePoolSize) {
        this.corePoolSize = corePoolSize;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public long getKeepAliveTime() {
        return keepAliveTime;
    }

    public void setKeepAliveTime(long keepAliveTime) {
        this.keepAliveTime = keepAliveTime;
    }

    public int getMaxDataLen() {
        return maxDataLen;
    }

    public void setMaxDataLen(int maxDataLen) {
        this.maxDataLen = maxDataLen;
    }

    public int getMaximumPoolSize() {
        return maximumPoolSize;
    }

    public void setMaximumPoolSize(int maximumPoolSize) {
        this.maximumPoolSize = maximumPoolSize;
    }

    public boolean isAllowCoreThdTimeOut() {
        return allowCoreThdTimeOut;
    }

    public void setAllowCoreThdTimeOut(boolean allowCoreThdTimeOut) {
        this.allowCoreThdTimeOut = allowCoreThdTimeOut;
    }

    public boolean isConnectRandom() {
        return connectRandom;
    }

    public void setConnectRandom(boolean connectRandom) {
        this.connectRandom = connectRandom;
    }

    public Map getParams() {
        return params;
    }

    public void setParams(Map params) {
        this.params = params;
    }

    public long getConnectRetryInterval() {
        return connectRetryInterval;
    }

    public void setConnectRetryInterval(long connectRetryInterval) {
        this.connectRetryInterval = connectRetryInterval;
    }

    public int getConnectRetryNum() {
        return connectRetryNum;
    }

    public void setConnectRetryNum(int connectRetryNum) {
        this.connectRetryNum = connectRetryNum;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("[" + id + "]:");
        sb.append("\n\taddress=" + showArray(address, ","));
        sb.append("\ttimeout=" + timeout);
        sb.append("\trandom=" + random);
        sb.append("\n\tcorePoolSize=" + corePoolSize);
        sb.append("\tmaximumPoolSize=" + maximumPoolSize);
        sb.append("\tkeepAliveTime=" + keepAliveTime);
        sb.append("\n\tmaxDataLen=" + maxDataLen);
        sb.append("\tencoding=" + encoding);
        sb.append("\n\tallowCoreThdTimeOut=" + allowCoreThdTimeOut);
        sb.append("\n\tconnectRandom=" + connectRandom);
        sb.append("\n\tconnectRetryNum=" + connectRetryNum);
        sb.append("\tconnectRetryInterval=" + connectRetryInterval);
        sb.append("\n\tproxyHost=" + proxyHost);
        sb.append("\tproxyPort=" + proxyPort);
        for (Iterator itr = params.keySet().iterator(); itr.hasNext();) {
            Object key = itr.next();
            sb.append("\n\t" + key).append("=").append(
                    YQUtil.getString(params.get(key)));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws ConfigurationException {
        ServerConfig config = new ServerConfig();
        XMLConfiguration xconfig = new XMLConfigurationExt4Null(
                "configuration/archive.xml");
        HierarchicalConfiguration sub = xconfig
                .configurationAt("servers.server(0)");
        config.read(sub);
        System.out.println(config);
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public String getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }

}

