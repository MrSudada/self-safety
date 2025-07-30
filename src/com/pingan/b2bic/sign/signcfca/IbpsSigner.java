package com.pingan.b2bic.sign.signcfca;

import com.cfca.util.pki.PKIException;
import com.cfca.util.pki.api.SignatureUtil;
import com.cfca.util.pki.cert.X509Cert;
import com.cfca.util.pki.cipher.JKey;
import com.cfca.util.pki.cipher.Session;

import java.io.UnsupportedEncodingException;

/**
 * <DL>
 * <DT><B> IBPS 网银互联项目加签类</B></DT>
 * <p>
 * <DD></DD>
 * </DL>
 * <p>
 *
 * <DL>
 * <DT><B>使用范例</B></DT>
 * <p>
 * <DD>使用范例说明</DD>
 * </DL>
 * <p>
 *
 * @author 薛蛟
 * @company 赞同科技
 * @date 2010-2010-6-8-下午09:38:05
 */
public class IbpsSigner {

	private Session session;

	private JKey priKey;

	private X509Cert cert;

	public IbpsSigner(Session session, JKey priKey, X509Cert cert) {
		this.session = session;
		this.priKey = priKey;
		this.cert = cert;
	}

	public byte[] signMsg(byte[] msg, boolean detatched)
			throws UnsupportedEncodingException, PKIException {
		X509Cert[] certs = new X509Cert[] { cert };
		byte[] b64SignData = null;
		SignatureUtil signUtil = new SignatureUtil();
		if (!detatched) {
			b64SignData = signUtil.p1SignMessage(msg, SignatureUtil.SHA1_RSA,
					priKey, session);
		} else {
			// 分离式消息签名
			b64SignData = signUtil.p7SignMessage(false, msg,
					SignatureUtil.SHA1_RSA, priKey, certs, session);
		}
		return b64SignData;
	}

	public X509Cert getCert() {
		return cert;
	}

}
