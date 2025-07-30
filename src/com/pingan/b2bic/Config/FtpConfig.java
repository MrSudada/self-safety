package com.pingan.b2bic.Config;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.pingan.b2bic.Util.StringTool;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;


public class FtpConfig extends BaseConfig {
	public static final String PROTOCOL_FTP = "FTP";

	public static final String PROTOCOL_SFTP = "SFTP";

	public static final String PROTOCOL_FTPS = "FTPS";

	/** 标识 */
	private String id;

	/** 协议: FTP、SFTP */
	private String protocol;

	/** 主机 */
	private String hostname;

	/** 端口 */
	private int port;

	/** 用户名 */
	private String ftpname;

	/** 用户密码 */
	private String ftppwd;

	/** 远程FTP服务器默认目录 */
	private String defaultDir;

	/** 主被动模式 */
	private boolean passivemode = true;

	/** socket读超时(ms) */
	private int soTimeout = 60000;

	/** 文件名编码 */
	private String encoding = "GBK";

	/** 文件传输异常重试次数**/
	private String exceptionRetryCts = "1";

	/** 文件传输异常重试间隔ms**/
	private String retryDelayTime="1000";

	/** 其它参数 */
	private Map params = new HashMap();

	/** 本地临时目录 */
	private String localTempDir;

	public void read(Configuration config) throws ConfigurationException {
		setId(config.getString("[@id]"));
		checkStrPpsIsNull(getId(), "ftp元素id属性未设置。");

		setProtocol(config.getString("protocol", PROTOCOL_FTP));

		setHostname(config.getString("hostname"));
		checkStrPpsIsNull(getHostname(), "ftp元素hostname未设置。");

		int defPort = protocol.equalsIgnoreCase(PROTOCOL_SFTP) ? 22 : 21;
		setPort(config.getInt("port", defPort));

		setFtpname(config.getString("ftpname"));
		checkStrPpsIsNull(getFtpname(), "ftp元素ftpname未设置。");

		setFtppwd(readPwdField(config.getString("ftppwd")));
		checkStrPpsIsNull(getFtppwd(), "ftp元素ftppwd未设置。");

		setPassivemode(config.getBoolean("passivemode", true));
		setSoTimeout(config.getInt("soTimeout", 60000));
		setEncoding(config.getString("encoding", "GBK"));
		setDefaultDir(config.getString("defaultDir"));

		this.setExceptionRetryCts(config.getString("exceptionRetryCts", "1"));
		this.setRetryDelayTime(config.getString("retryDelayTime", "1000"));

		setLocalTempDir(config.getString("localTempDir", "tmp"));
		BaseConfig.readParams(config, params);
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("[" + id + "]:");
		sb.append("\n\tprotocol=").append(protocol);
		sb.append("\thostname=").append(hostname);
		sb.append("\tport=").append(port);
		sb.append("\tftpname=").append(ftpname);
		sb.append("\tpassivemode=").append(passivemode);
		sb.append("\tsoTimeout=").append(soTimeout);
		sb.append("\tencoding=").append(encoding);
		sb.append("\texceptionRetryCts=").append(exceptionRetryCts);
		sb.append("\tretryDelayTime=").append(retryDelayTime);
		if (defaultDir != null) {
			sb.append("\n\tdefaultDir=").append(defaultDir);
		}
		for (Iterator itr = params.keySet().iterator(); itr.hasNext();) {
			Object key = itr.next();
			sb.append("\n\t" + (String) key).append("=").append(
					StringTool.getString(params.get(key)));
		}
		return sb.toString();
	}

	public Map getParams() {
		return params;
	}

	public void setParams(Map params) {
		this.params = params;
	}

	public String getDefaultDir() {
		return defaultDir;
	}

	public void setDefaultDir(String defaultDir) {
		this.defaultDir = defaultDir;
	}

	public String getEncoding() {
		return encoding;
	}

	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	public String getFtpname() {
		return ftpname;
	}

	public void setFtpname(String ftpname) {
		this.ftpname = ftpname;
	}

	public String getFtppwd() {
		return ftppwd;
	}

	public void setFtppwd(String ftppwd) {
		this.ftppwd = ftppwd;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public boolean isPassivemode() {
		return passivemode;
	}

	public void setPassivemode(boolean passivemode) {
		this.passivemode = passivemode;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}



	public int getSoTimeout() {
		return soTimeout;
	}

	public void setSoTimeout(int soTimeout) {
		this.soTimeout = soTimeout;
	}

	public String getLocalTempDir() {
		return localTempDir;
	}

	public void setLocalTempDir(String localTempDir) {
		this.localTempDir = localTempDir;
	}

	public String getExceptionRetryCts() {
		return exceptionRetryCts;
	}

	public void setExceptionRetryCts(String exceptionRetryCts) {
		this.exceptionRetryCts = exceptionRetryCts;
	}

	public String getRetryDelayTime() {
		return retryDelayTime;
	}

	public void setRetryDelayTime(String retryDelayTime) {
		this.retryDelayTime = retryDelayTime;
	}
}
