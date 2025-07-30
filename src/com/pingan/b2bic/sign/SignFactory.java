package com.pingan.b2bic.sign;

import cn.com.infosec.keytool.KeyToolAPI;
import com.pingan.b2bic.Exception.CodeAndMsgException;
import com.pingan.b2bic.Exception.ErrorInfo;
import com.pingan.b2bic.sign.ISign;
import com.pingan.b2bic.sign.ISignFactory;
import com.pingan.b2bic.sign.signcfca.CfcaSign;
import com.pingan.b2bic.sign.usbkey.IUKeyType;
import com.pingan.b2bic.sign.usbkey.SM2Soft;
import com.pingan.b2bic.Util.StringTool;

import java.security.cert.X509Certificate;
import java.util.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SignFactory implements ISignFactory {
    private static final Log log = LogFactory.getLog(SignFactory.class);

    private CfcaSign cfcaSign = null;

    private static Object locker = new Object();

    private static Set<String> methods = new HashSet<String>();

    static {
        methods.add("sign");
        methods.add("hashAndSign");
    }

    public ISign createSignToolWithPath(String pfxPath, String pfxPwd,String signMode ) throws Exception {
        Config config = Config.getInstance();
        ISign tool = createSignTool(signMode, null,pfxPath,pfxPwd);
        return tool;
    }

    public ISign createSignTool() throws Exception {
        Config config = Config.getInstance();
        String type = config.getSignMode();
        ISign tool = createSignTool(type, null);
        return tool;
    }

    public ISign createSignTool(String type, Map param, String pfxPath, String pfxPwd) throws Exception {
        Config config = Config.getInstance();
        if (type.equalsIgnoreCase(IUKeyType.SOFT)) {
            if (param == null || param.size() == 0) {
                // 从配置文件中读取参数
                synchronized (locker) {
                    if (cfcaSign == null) {
                        cfcaSign = new CfcaSign();
                        cfcaSign.setCaCertPath(config.getCaCertPath());
                        cfcaSign.setCrlPath(config.getCrlPath());
                        cfcaSign.setHashAlg(config.getHashAlg());
                        cfcaSign.setPfxPath(pfxPath);
                        cfcaSign.setPfxPwd(pfxPwd);
                        cfcaSign.setCheckCert(config.isCheckBankSign());
                        cfcaSign.setVerifyCertDNs(config.getBankCertDN());
                        try {
                            cfcaSign.init();
                        } catch (Exception e) {
                            log.error("Create signature class exception：" + StringTool.getErrorStack(e));
                            CodeAndMsgException exp = new CodeAndMsgException();
                            exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                            exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                            throw exp;
                        }
                    }
                    return cfcaSign;
                }
            } else {
                // Web端访问
                CfcaSign signTool = new CfcaSign();
                signTool.setCaCertPath((String) param.get("caCertPath"));
                signTool.setCrlPath((String) param.get("crlPath"));
                String hashAlg = (String) param.get("hashAlg");
                if (hashAlg == null) {
                    hashAlg = Config.getInstance().getHashAlg();
                }
                signTool.setHashAlg(hashAlg);
                signTool.setPfxPath((String) param.get("pfxPath"));
                signTool.setPfxPwd((String) param.get("pfxPwd"));
                try {
                    signTool.init();
                } catch (Exception e) {
                    log.error("Create signature class exception：" + StringTool.getErrorStack(e));
                    CodeAndMsgException exp = new CodeAndMsgException();
                    exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                    exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                }
                return signTool;
            }
        } else if (type.equalsIgnoreCase(IUKeyType.SM2_FILE))  {
            SM2Soft tool = new SM2Soft();
            tool.setHashAlg(config.getHashAlg());

            //读取证书subject
            X509Certificate cert = KeyToolAPI.getSignCertInPFX( pfxPath , pfxPwd ) ;
            String subject = cert.getSubjectDN().getName();
            tool.setSubject(subject);
            return tool;
        }else{
            log.error( "Create signature class exception: Unsupported signature type:" + type);
            return null;
        }
    }


    public ISign createSignTool(String type, Map param) throws Exception {
        Config config = Config.getInstance();
        if (type.equalsIgnoreCase(IUKeyType.SOFT)) {
            if (param == null || param.size() == 0) {
                // 从配置文件中读取参数
                synchronized (locker) {
                    if (cfcaSign == null) {
                        cfcaSign = new CfcaSign();
                        cfcaSign.setCaCertPath(config.getCaCertPath());
                        cfcaSign.setCrlPath(config.getCrlPath());
                        cfcaSign.setHashAlg(config.getHashAlg());
                        cfcaSign.setPfxPath(config.getPfxPath());
                        cfcaSign.setPfxPwd(config.getPfxPwd());
                        cfcaSign.setCheckCert(config.isCheckBankSign());
                        cfcaSign.setVerifyCertDNs(config.getBankCertDN());
                        try {
                            cfcaSign.init();
                        } catch (Exception e) {
                            log.error("Create signature class exception：" + StringTool.getErrorStack(e));
                            CodeAndMsgException exp = new CodeAndMsgException();
                            exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                            exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                            throw exp;
                        }
                    }
                    return cfcaSign;
                }
            } else {
                // Web端访问
                CfcaSign signTool = new CfcaSign();
                signTool.setCaCertPath((String) param.get("caCertPath"));
                signTool.setCrlPath((String) param.get("crlPath"));
                String hashAlg = (String) param.get("hashAlg");
                if (hashAlg == null) {
                    hashAlg = Config.getInstance().getHashAlg();
                }
                signTool.setHashAlg(hashAlg);
                signTool.setPfxPath((String) param.get("pfxPath"));
                signTool.setPfxPwd((String) param.get("pfxPwd"));
                try {
                    signTool.init();
                } catch (Exception e) {
                    log.error("Create signature class exception：" + StringTool.getErrorStack(e));
                    CodeAndMsgException exp = new CodeAndMsgException();
                    exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                    exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                }
                return signTool;
            }
        } else if (type.equalsIgnoreCase(IUKeyType.SM2_FILE))  {
            SM2Soft tool = new SM2Soft();
            tool.setHashAlg(config.getHashAlg());

            //读取证书subject
            X509Certificate cert = KeyToolAPI.getSignCertInPFX( config.getPfxPath() , config.getPfxPwd() ) ;
            String subject = cert.getSubjectDN().getName();
            tool.setSubject(subject);
            return tool;
        }else{
            log.error( "Create signature class exception: Unsupported signature type:" + type);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public List findCerts(String type) throws Exception {
        List ret = null;
        if (type.equalsIgnoreCase(IUKeyType.SOFT)) {
            synchronized (locker) {
                if (cfcaSign == null) {
                    Config config = Config.getInstance();
                    cfcaSign = new CfcaSign();
                    cfcaSign.setCaCertPath(config.getCaCertPath());
                    cfcaSign.setCrlPath(config.getCrlPath());
                    cfcaSign.setHashAlg(config.getHashAlg());
                    cfcaSign.setPfxPath(config.getPfxPath());
                    cfcaSign.setPfxPwd(config.getPfxPwd());
                    cfcaSign.setCheckCert(config.isCheckBankSign());
                    cfcaSign.setVerifyCertDNs(config.getBankCertDN());
                    try {
                        cfcaSign.init();
                    } catch (Exception e) {
                        log.error("创建签名类异常：" + StringTool.getErrorStack(e));
                        CodeAndMsgException exp = new CodeAndMsgException();
                        exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                        exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                        throw exp;
                    }
                }
                ret = new ArrayList();
                ret.add(cfcaSign.getSubjectDN());
            }
        } else {
            throw new IllegalArgumentException("Signature method not supported:" + type);
        }
        return ret;
    }


    @Override
    public ISign createVerifySignTool() {
        Config config = Config.getInstance();
        //从配置文件中读取参数
        synchronized (locker) {
            if (cfcaSign == null) {
                cfcaSign = new CfcaSign();
                cfcaSign.setCaCertPath(config.getCaCertPath());
                cfcaSign.setCrlPath(config.getCrlPath());
                cfcaSign.setHashAlg(config.getHashAlg());

                cfcaSign.setCheckCert(config.isCheckBankSign());
                cfcaSign.setVerifyCertDNs(config.getBankCertDN());
                try {
                    cfcaSign.init();
                } catch (Exception e) {
                    log.error("创建签名类异常：" + StringTool.getErrorStack(e));
                    CodeAndMsgException exp = new CodeAndMsgException();
                    exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
                    exp.setErrorMsg(ErrorInfo.get("Sign_INIT"));
                    throw exp;
                }
            }
            return cfcaSign;
        }
    }


}

