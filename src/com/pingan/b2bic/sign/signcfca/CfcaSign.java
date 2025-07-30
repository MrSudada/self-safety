package com.pingan.b2bic.sign.signcfca;

import com.cfca.util.pki.PKIException;
import com.cfca.util.pki.api.CertUtil;
import com.cfca.util.pki.api.KeyUtil;
import com.cfca.util.pki.cert.X509Cert;
import com.cfca.util.pki.cipher.JCrypto;
import com.cfca.util.pki.cipher.JKey;
import com.cfca.util.pki.cipher.Session;
import com.cfca.util.pki.crl.X509CRL;
import com.pingan.b2bic.Exception.CodeAndMsgException;
import com.pingan.b2bic.Exception.ErrorInfo;
import com.pingan.b2bic.sign.AbstractSign;
import com.pingan.b2bic.Util.StringTool;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Set;

/**
 * RSA_SOFT文件证书
 * **/
public class CfcaSign extends AbstractSign {
	private static final Log log = LogFactory.getLog(CfcaSign.class);

	private Session pkiSession;

	private CertDNVerifer verifyTool;

	private IbpsSigner signerTool;

	/** CA证书链路径 */
	private String caCertPath;

	/** 撤销证书链路径 */
	private String crlPath;
	
	/** 私有证书路径 */
	private String pfxPath;

	/** 私有证书密码 */
	private String pfxPwd;

	private boolean checkCert = true;
	
	/** 待校验证书DN号 */
	private Set<String> verifyCertDNs;

	public void init() throws Exception {
		log.debug("Signature tool is initializing...");
		Provider bcProvider = Security.getProvider("BC");
		if (bcProvider == null) {
			Security
					.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		}
		try {
			JCrypto jcrypto = JCrypto.getInstance();
			jcrypto.initialize(JCrypto.JSOFT_LIB, null);
			pkiSession = jcrypto.openSession(JCrypto.JSOFT_LIB);
		} catch (PKIException e) {
			log.error("Initialization exception:" + StringTool.getErrorStack(e));
			throw e;
		}
		// ����˽��֤��
		if (pfxPath != null) {
			X509Cert cert = CertUtil.getCert(pfxPath, pfxPwd);
			JKey key = KeyUtil.getPriKey(pfxPath, pfxPwd);
			signerTool = new IbpsSigner(pkiSession, key, cert);
			log.debug("private certificate: " + cert.getSubject());
		} else {
			log.debug("Soft signature certificate is not set");
		}

		verifyTool = new CertDNVerifer(pkiSession);
		verifyTool.setCheckCert(checkCert);
		if (checkCert) {
			// 证书链
			if (caCertPath != null) {
				try {
					X509Cert[] caCerts = CertUtil.parseP7b(caCertPath);
					for (int i = 0; i < caCerts.length; i++) {
						log.info("Ca certificate[" + (i + 1) + "]: "
								+ caCerts[i].getSubject());
					}
					verifyTool.setCaCerts(caCerts);
				} catch (Exception e) {
					log.error("Initialization certificate chain exception:" + StringTool.getErrorStack(e));
					throw e;
				}
			} else {
				log.error("Initialization exception: certificate chain not set");
			}
			// 撤销证书链
			if (crlPath != null) {
				ByteArrayOutputStream bou = null;
				InputStream is = null;
				try {
					is = new FileInputStream(crlPath);
					bou = new ByteArrayOutputStream();
					byte[] buffer = new byte[8192];
					int readed = -1;
					while ((readed = is.read(buffer)) != -1) {
						bou.write(buffer, 0, readed);
					}
					X509CRL crl = new X509CRL(bou.toByteArray());
					verifyTool.setCrl(crl);
				} catch (Exception e) {
					log.error("Failed to initialize revocation list：" + StringTool.getErrorStack(e));
					throw e;
				} finally {
					if (is != null) {
						try {
							is.close();
						} catch (Exception e) {
						}
					}
					if (bou != null) {
						try {
							bou.close();
						} catch (Exception e) {
						}
					}
				}
			} else {
				log.debug("CRL certificate is unset.");
			}
			// 授权证书DN
			if (verifyCertDNs == null || verifyCertDNs.size() == 0) {
				log.debug("Initialization exception: signature verification certificate DN is not set");
			} else {
				log.debug("Certificate of authorization:" + verifyCertDNs.toString());
				verifyTool.setDns(verifyCertDNs);
			}
			//verifyTool.setDns(verifyCertDNs);
		} else {
			log.debug("Soft signature does not verify certificate");
		}
		log.debug("Initialization of signature tool is finished.");
	}

	@Override
	public byte[] getCert() throws Exception {
		checkSignInit();		
		X509Cert cert = signerTool.getCert();
		return cert.getEncoded();
	}

	@Override
	public String getSubjectDN() throws Exception {
		checkSignInit();		
		X509Cert cert = signerTool.getCert();
		return cert.getSubject();
	}

	@Override
	public byte[] sign(byte[] hash) throws Exception {
		checkSignInit();		
		return signerTool.signMsg(hash, true);
	}

	@Override
	public boolean verify(byte[] hash, byte[] signData) throws Exception {
		checkVerifyInit();		
		return verifyTool.verifyMsg(hash, signData, null, true);
	}

	private void checkSignInit() {
		if (signerTool == null) {
			log.error("Soft signature object not initialized");
			CodeAndMsgException exp = new CodeAndMsgException();
			exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
			exp.setErrorMsg(ErrorInfo.get("Sign_NOINIT"));
			throw exp;					
		}
	}
	
	private void checkVerifyInit() {
		if (verifyTool == null) {
			log.error("Soft signature object not initialized");
			CodeAndMsgException exp = new CodeAndMsgException();
			exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
			exp.setErrorMsg(ErrorInfo.get("Sign_NOINIT"));
			throw exp;					
		}
	}
	
	public String getCaCertPath() {
		return caCertPath;
	}

	public void setCaCertPath(String caCertPath) {
		this.caCertPath = caCertPath;
	}

	public String getCrlPath() {
		return crlPath;                                                                                                                                                                                                                                          
	}

	public void setCrlPath(String crlPath) {
		this.crlPath = crlPath;
	}

	public String getPfxPath() {
		return pfxPath;
	}

	public void setPfxPath(String pfxPath) {
		this.pfxPath = pfxPath;
	}

	public String getPfxPwd() {
		return pfxPwd;
	}

	public void setPfxPwd(String pfxPwd) {
		this.pfxPwd = pfxPwd;
	}

	public boolean isCheckCert() {
		return checkCert;
	}

	public void setCheckCert(boolean checkCert) {
		this.checkCert = checkCert;
	}

	public Set<String> getVerifyCertDNs() {
		return verifyCertDNs;
	}

	public void setVerifyCertDNs(Set<String> verifyCertDNs) {
		this.verifyCertDNs = verifyCertDNs;
	}
	
}
