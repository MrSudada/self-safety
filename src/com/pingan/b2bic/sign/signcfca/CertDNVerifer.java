package com.pingan.b2bic.sign.signcfca;

import com.cfca.util.pki.PKIException;
import com.cfca.util.pki.api.CertUtil;
import com.cfca.util.pki.api.SignatureUtil;
import com.cfca.util.pki.cert.X509Cert;
import com.cfca.util.pki.cipher.Session;
import com.cfca.util.pki.crl.X509CRL;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * 签名校验器
 * <p>
 * 校验签名证书DN号
 *
 * @author ywb
 *
 */
public class CertDNVerifer {
	private static final Log log = LogFactory.getLog(CertDNVerifer.class);

	private Session session;

	/** 是否校验证书 */
	private boolean checkCert = true;

	/** 已授权证书DN号 */
	private Set<String> dns;

	private X509Cert[] caCerts;

	private X509CRL crl;

	public CertDNVerifer(Session session) {
		this.session = session;
	}

	public boolean verifyMsg(byte[] srcBytes, byte[] signData,
                             X509Cert signCert, boolean detatched) throws Exception {
		X509Cert cert = null;
		// 1.验证签名是否正确
		SignatureUtil signUtil = new SignatureUtil();
		if (detatched) {
			if (!signUtil.p7VerifySignMessageDetached(srcBytes, signData,
					session)) {
				log.error("Incorrect signature");
				return false;
			}
			// 获取签名者证书
			X509Cert[] x509Certs = signUtil.getSigerCert();
			cert = x509Certs[0];
		} else {
			if (!signUtil.p1VerifySignMessage(srcBytes, signData,
					"SHA1withRSAEncryption", signCert, session)) {
				log.error("Incorrect signature");
				return false;
			}
			cert = signCert;
		}
		if (log.isDebugEnabled()) {
			log.debug("Signer=" + cert.getSubject());
		}
		if (!checkCert) {
			return true;
		}

		// 2.检查DN号
		String dn = getCN(cert.getSubject());
		if (!dns.contains(dn)) {
			log.error("Unauthorized signature certificate DN:[" + dn + "]");
			return false;
		}

		// 3.校验证书有效期
//		if (!CertUtil.verifyCertDate(cert)) {
//			log.error("证书过期，证书有效期截止日期：" + cert.getNotAfter());
//			return false;
//		}

		// 4.校验证书链
		if (caCerts == null) {
			log.error("Certificate chain not set");
			return false;
		} else {
			try {
				if(!CertUtil.verifyCertSign(cert, caCerts, session)) {
					log.error("Illegal signature certificate");
					return false;
				}
			} catch(PKIException e) {
				log.error("Signature verification failed：" + e.getMessage());
				return false;
			}
		}

		// 5.校验撤销证书链
		if (crl != null) {
			if (crl.isRevoke(cert)) {
				log.error("The certificate has been revoked");
				return false;
			}
		}
		return true;
	}

	// 抽取CN号，删除DN串前后和中间空格去掉，转换成大写
	private String getCN(String dn) throws Exception {
		int start = dn.toUpperCase().indexOf("CN=");
		if (start == -1) {
			log.error("Illegal certificate subject format：" + dn);
			throw new Exception("Illegal certificate subject format：" + dn);
		}
		int end = dn.indexOf(",", start);
		if (end == -1) {
			end = dn.length();
		}
		StringBuilder sb = new StringBuilder(end - start - 3);
		for (int i = start + 3; i < end; i++) {
			if (!Character.isWhitespace(dn.charAt(i))) {
				sb.append(dn.charAt(i));
			}
		}
		return sb.toString().toUpperCase();
	}

	public Set<String> getDns() {
		return dns;
	}

	public void setDns(Set<String> dns) {
		Set<String> tmp = new HashSet<String>();
		// 抽取CN
		for (String item : dns) {
			try {
				String dn = getCN(item);
				tmp.add(dn);
			} catch(Exception e) {
				log.error(e);
			}
		}
		this.dns = tmp;
	}

	public boolean isCheckCert() {
		return checkCert;
	}

	public void setCheckCert(boolean checkCert) {
		this.checkCert = checkCert;
	}

	public X509Cert[] getCaCerts() {
		return caCerts;
	}

	public void setCaCerts(X509Cert[] caCerts) {
		this.caCerts = caCerts;
	}

	public X509CRL getCrl() {
		return crl;
	}

	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}

}
