package com.pingan.b2bic.sign;

import com.pingan.b2bic.Config.*;
import com.pingan.b2bic.Exception.ErrorInfo;
import com.pingan.b2bic.sign.usbkey.IUKeyType;
import com.pingan.b2bic.Util.StringTool;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.util.*;

/**
 * 系统配置信息
 *
 * @author ywb
 * @author 赞同
 * @version 1.0 2013-09-10
 */
public class Config {
    private static final Log log = LogFactory.getLog(Config.class);

    /** 银行端配置 */
    private static final String BANK_CONFIG = "cfgbank.xml";

    /** 签名配置 */
    private static final String SIGN_CONFIG = "cfgsign.xml";

    /** 错误信息配置文件 */
    public static final String ERRORINFO_CONFIG = "errInfo.properties";

    public static final String DEFAULT_HASHALG = "SHA1";

    // 服务提供方
    public static final String SERVER_BANKOUT = "bankOut";
    // FTP服务
    public static final String FTPSERVER_BANK = "bankFtp";

    /** 临时目录 */
    private String tmpdir = "tmp";

    private static Config config;

    private static Object plock = new Object();

    /** 上行签名交易代码集 */
    private Set<String> signTradeCodes_up = new HashSet<String>();

    /** 下行非签名交易代码集 */
    private Set<String> signTradeCodes_down = new HashSet<String>();

    /** 配置文件目录 */
    private String configDir;

    /** 银行接出 */
    private MultiProtocolServerConfig bankOutCfg;

    public FtpConfig getBankftpCfg() {
        return bankftpCfg;
    }

    /** 银行Ftp配置 */
    private FtpConfig bankftpCfg;

    /** 签名方式(普通usbkey、捷德无驱、软签等) */
    private String signMode;

    /** 签名证书DN */
    private String certDn;

    /** 验签名方式 */
    private String verifySignMode;

    /** Hash值算法 */
    private String hashAlg;

    /** CA证书链目录 */
    private String caCertPath;

    /** 撤销证书链目录 */
    private String crlPath;

    /** 私有证书路径 */
    private String pfxPath;

    /** 私有证书密码 */
    private String pfxPwd;

    /** 验签是否校验证书 */
    private boolean checkBankSign;

    /** 行方签名证书DN */
    private Set<String> bankCertDN = new HashSet<String>();

    /** 密码字段是否加密 */
    private boolean fieldEncry;

    /** 密码字段读写器 */
    private IPasswordReader pwdReader;

    public static Config getInstance() {
        if (config == null) {
            synchronized (plock) {
                config = new Config();
            }
        }
        return config;
    }

    public Config() {
        try {
            if (log.isInfoEnabled()) {
                log.info("Load configuration file...");
            }
                configDir = System.getProperty("user.dir")
                        + File.separator
                        + "configuration"
                        + File.separator;
//            String errorInfoCfgPath = configDir + ERRORINFO_CONFIG;
//            InputStream ins = null;
//            try {
//                ins = new BufferedInputStream(new FileInputStream(
//                        errorInfoCfgPath));
//                Properties infoPpt = new Properties();
//                infoPpt.load(ins);
//                ErrorInfo.ppt.putAll(infoPpt);
//            } catch (IOException e) {
//                log.error("加载错误信息文件异常:" + StringTool.getErrorStack(e));
//                throw new RuntimeException(e);
//            } finally {
//                if (ins != null) {
//                    try {
//                        ins.close();
//                    } catch (Exception e) {
//                        log.error(e);
//                    }
//                }
//            }
            ErrorInfo info = new ErrorInfo();
            readSignCfg();
            readBankCfg();

            if (log.isInfoEnabled()) {
                try {
                    StringBuffer sb = StringTool
                            .printObject(this, Config.class);
                    log.info("read Config:" + sb.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                log.info("End of profile loading");
            }
        } catch (NoSuchElementException e) {
            log.error( "The configuration item is not set or the value is empty：" + e.getMessage());
            throw e;
        } catch (ConfigurationException e) {
            log.error("Error reading configuration item：" + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private XMLConfiguration getXMLCfgObj(String filePath) {
        String path = configDir + filePath;
        try {

            XMLConfiguration cfg = new XMLConfigurationExt4Null();
            cfg.setDelimiterParsingDisabled(true);
            cfg.load(path);
            return cfg;
        } catch (Exception e) {
            log.error("Failed to load configuration file:[" + path + "]" + e.toString());
            throw new RuntimeException(e);
        }
    }

    /** 读取签名配置文件 */
    private void readSignCfg() {
        XMLConfiguration signConfig = getXMLCfgObj(SIGN_CONFIG);
        fieldEncry = signConfig.getBoolean("pwdEncry", true);
        if (fieldEncry) {
            pwdReader = new DesReader();
        } else {
            pwdReader = new NoCryptReader();
        }
        hashAlg = signConfig.getString("signopt.hashAlg", DEFAULT_HASHALG);
        signMode = signConfig.getString("signopt.signMode", IUKeyType.SOFT);
        certDn = signConfig.getString("signopt.certDn");
        pfxPath = signConfig.getString("signopt.pfxPath");
        if (pfxPath != null && pfxPath.trim().length() != 0) {
            pfxPwd = signConfig.getString("signopt.pfxPwd");
            try {
                pfxPwd = pwdReader.read(pfxPwd);
            } catch (Exception e) {
                log.error( "Certificate password setting error");
            }
        }

        verifySignMode = signConfig.getString("signopt.verifySignMode",
                IUKeyType.SOFT);
        caCertPath = signConfig.getString("signopt.caCertPath");
        crlPath = signConfig.getString("signopt.crlPath");

        checkBankSign = signConfig.getBoolean("signopt.checkBankSign", true);
        String dn = signConfig.getString("signopt.bankCertDN");
        if (dn != null) {
            String[] dnarr = split(dn, ';');
            for (int i = 0; i < dnarr.length; i++) {
                String s = dnarr[i].trim();
                if (s.length() > 0) {
                    bankCertDN.add(s);
                }
            }
        }
        String tradeUp = signConfig.getString("signTradeCodes.up");
        if (tradeUp != null) {
            String[] uparr = tradeUp.split(";");
            for (int i = 0; i < uparr.length; i++) {
                String s = uparr[i].trim();
                if (s.length() > 0) {
                    signTradeCodes_up.add(s);
                }
            }
        }
        String tradeDown = signConfig.getString("signTradeCodes.down");
        if (tradeDown != null) {
            String[] downarr = tradeDown.split(";");
            for (int i = 0; i < downarr.length; i++) {
                String s = downarr[i].trim();
                if (s.length() > 0) {
                    signTradeCodes_down.add(s);
                }
            }
        }
    }

    /**
     * 拆字符
     * @param src
     * @param c 分隔符
     * @return
     */
    private static String[] split(String src, char c) {
        // 不允许单个字符串首字符是分隔符
        List<String> lst = new ArrayList<String>();
        char[] chars = src.toCharArray();
        StringBuilder sb = new StringBuilder(src.length());
        int p = 0;
        while (p < chars.length) {
            if (chars[p] != c) {
                sb.append(chars[p]);
            } else {
                if (p + 1 == chars.length) {
                    // 字符串末尾
                    break;
                } else if (chars[p + 1] != c) {
                    lst.add(sb.toString().trim());
                    sb.setLength(0);
                } else {
                    sb.append(c); // 连续两个c,表示非分隔符，替换成一个有效字符
                    p++;
                }
            }
            p++;
            continue;
        }
        String last = sb.toString().trim();
        if (last.length() != 0) {
            lst.add(last);
        }
        return lst.toArray(new String[0]);
    }

    /** 读取银行端配置文件 */
    private void readBankCfg() throws ConfigurationException {
        XMLConfiguration bankConfig = getXMLCfgObj(BANK_CONFIG);
        // 读取服务端配置项
        List server = bankConfig.configurationsAt("servers.server");
        for (Iterator itr = server.iterator(); itr.hasNext();) {
            HierarchicalConfiguration sub = (HierarchicalConfiguration) itr
                    .next();
            String id = sub.getString("[@id]");
            if (SERVER_BANKOUT.equalsIgnoreCase(id)) {
                String protocol = sub.getString("protocol",
                        IProtocol.PROTOCOL_HTTPS);
                bankOutCfg = (MultiProtocolServerConfig) MultiProtocolServerConfig
                        .createServerConfig(protocol);
                bankOutCfg.setPwdReader(pwdReader);
                bankOutCfg.read(sub);
            } else {
                log.warn("Uplink out service not used：" + id);
            }
        }
        if (bankOutCfg == null) {
            throw new NoSuchElementException("Uplink outgoing service is not configured");
        }
        if (bankOutCfg instanceof HttpsServerConfig)
        {
            boolean checkBankCert = bankConfig.getBoolean("checkBankCert", false);
            ((HttpsServerConfig)bankOutCfg).setAuthSrv(checkBankCert);
        }

        // 读取FTP配置
        List ftplst = bankConfig.configurationsAt("ftpServers.server");
        for (Iterator itr = ftplst.iterator(); itr.hasNext();) {
            HierarchicalConfiguration sub = (HierarchicalConfiguration) itr
                    .next();
            String id = sub.getString("[@id]");
            if (FTPSERVER_BANK.equalsIgnoreCase(id)) {
                bankftpCfg = new FtpConfig();
                bankftpCfg.setPwdReader(pwdReader);
                bankftpCfg.read(sub);
                bankftpCfg
                        .setLocalTempDir(StringTool.addDirSuff(tmpdir) + "down");
            } else {
                log.warn("未知的FTP服务器：" + id);
            }
        }
        if (bankftpCfg == null) {
            throw new NoSuchElementException("未配置行方FTP");
        }

    }

    public MultiProtocolServerConfig getBankOutCfg() {
        return bankOutCfg;
    }

    public String getHashAlg() {
        return hashAlg;
    }

    public String getSignMode() {
        return signMode;
    }

    public String getCertDn() {
        return certDn;
    }

    public String getCaCertPath() {
        return caCertPath;
    }

    public String getCrlPath() {
        return crlPath;
    }

    public String getPfxPath() {
        return pfxPath;
    }

    public String getPfxPwd() {
        return pfxPwd;
    }


    public Set<String> getBankCertDN() {
        return bankCertDN;
    }

    public boolean isCheckBankSign()
    {
        return checkBankSign;
    }

}
