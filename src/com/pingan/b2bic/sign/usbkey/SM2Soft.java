package com.pingan.b2bic.sign.usbkey;

import com.infosec.NetSignServer;
import com.pingan.b2bic.Exception.CodeAndMsgException;
import com.pingan.b2bic.Exception.ErrorInfo;
import com.pingan.b2bic.sign.AbstractSign;
import com.pingan.b2bic.sign.usbkey.winapi.LastErrorException;
import com.pingan.b2bic.Util.StringTool;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.io.*;

/**
 * 国密文件证书签名
 * @author guolitao
 * */
public class SM2Soft extends AbstractSign {
	private static final Log logger = LogFactory.getLog(SM2Soft.class);
	private String basePath = "configuration";

	/** 使用证书主体 */
	private String subject;

	public byte[] getCert() throws Exception {
		throw new RuntimeException("Operationg is unsupported");
	}

	public String getSubjectDN() throws Exception {
		checkInit();
		return subject;
	}

	@Override
	public byte[] hashAndSign(byte[] data) throws Exception {
		//SM2 jar会对原数据进行签名
		return sign(data);
	}
	public byte[] sign(byte[] hash) throws Exception {
		checkInit();
		if (logger.isDebugEnabled()) {
			logger.debug("Signature certificate DN：" + subject);
		}
		try {

			BufferedInputStream inputStream;
			ResourceBundle rb =null;
			String proFilePath = "netsign.properties";
			File f = new File(basePath, proFilePath);
			try {
				inputStream = new BufferedInputStream(new FileInputStream(f));
				rb = new PropertyResourceBundle(inputStream);
				inputStream.close();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			NetSignServer netSign = new NetSignServer(rb);
			//System.out.println("src>>>>"+new String(hash));
			netSign.NSSetPlainText(hash);
//			String  certInfo= netSign.NSGetSignerCertInfo(1);
//			System.out.println("certInfo>>>>"+certInfo);

			byte[] ret = netSign.NSAttachedSign(subject);
			int retV=netSign.getLastErrnum();

			//System.out.println("sign>>>>"+new String(subject) + "||" +new String(ret));
			return  (new String(subject) + "||" +new String(ret)).getBytes();
		} catch (LastErrorException e) {
			logger.error("Signature Exception：" + StringTool.getErrorStack(e));
			CodeAndMsgException e1 = new CodeAndMsgException();
			e1.setErrorCode(ErrorInfo.get("Sign_CODE"));
			e1.setErrorMsg(":[0x"
					+ Integer.toHexString(e.getCode()).toUpperCase() + "]"
					+ e.getMessage());
			throw e1;
		}
	}

	public boolean verify(byte[] hash, byte[] signData) throws Exception {
		throw new RuntimeException("Operationg is unsupported");
	}

	private void checkInit() {
		if (subject == null) {
			CodeAndMsgException exp = new CodeAndMsgException();
			exp.setErrorCode(ErrorInfo.get("Sign_CODE"));
			exp.setErrorMsg(ErrorInfo.get("Sign_NOINIT"));
			throw exp;
		}
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

}
