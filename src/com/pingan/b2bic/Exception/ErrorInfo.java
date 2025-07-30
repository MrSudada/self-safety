package com.pingan.b2bic.Exception;

import java.util.Properties;

/* 
 * @author yuanwenbo
 * @author 赞同科技
 * @version 1.00, 2007-7-26
 */
public class ErrorInfo {
	public static final String ERRORCODE_OK = "0000";

	public static final String ERRORMSG_OK = "OK";

	public static final String ERRORCODE_0001 = "0001";

	public static final String ERRORMSG_0001 = "Parsing of Request is error";

	public static final String ERRORCODE_0002 = "0002";

	public static final String ERRORMSG_0002 = "Response message is error";

	public static final String ERRORCODE_0003 = "0003";

	public static final String ERRORMSG_0003 = "Request is unsupported";

	public static final String ERRORCODE_0004 = "0004";

	public static final String ERRORMSG_0004 = "The processing of request is error";

	public static final String ERRORCODE_0005 = "0005";

	public static final String ERRORMSG_0005 = "Receive request IO exception";

	public static final String ERRORCODE_0006 = "0006";

	public static final String ERRORMSG_0006 = "filed do not exist";

	public static final String ERRORCODE_0007 = "0007";

	public static final String ERRORMSG_0007 = "Application exception";

	public static final String ERRORCODE_0008 = "0008";

	public static final String ERRORMSG_0008 = "Request message exception";

	public static final String ERRORCODE_0010 = "0010"; // 字段值非法

	public static final String CODE_OK = "000000";

	public static final String MSG_OK = "Deal success";

	public static final String MSG_OK_RCV = "Deal accepted successfully";

	public static final String CODE_0001 = "E90001";

	public static final String MSG_0001 = "Parsing of Request is errorr";

	public static final String CODE_0002 = "E90002";

	public static final String MSG_0002 = "Response message is error";

	public static final String CODE_0003 = "E90003";

	public static final String MSG_0003 = "Request is unsupported";

	public static final String CODE_0004 = "E90004";

	public static final String MSG_0004 = "The processing of request is error";

	public static final String CODE_0005 = "E90005";

	public static final String MSG_0005 = "Receive request IO exception";

	public static final String CODE_0006 = "E90006";

	public static final String MSG_0006 = "filed do not exist";

	public static final String CODE_0007 = "E90007";

	public static final String MSG_0007 = "Application is error";

	public static final String CODE_0008 = "E90008";

	public static final String MSG_0008 = "Request message is illegal";

	public static final String DupTradSn_CODE = "E00001";

	public static final String DupTradSn_MSG = "Repetitive TranSn";

	public static final String Verify_CODE = "E00002";

	public static final String Verify_MSG = "Signature error";

	public static final String Verify_MSG1 = "Signature verification exception";

	public static final String Sign_CODE = "E00003";

	public static final String Sign_MSG = "Signature exception";

	public static final String NoExist_CODE = "E00004";

	public static final String NoExist_MSG = "The record do not exist";

	public static Properties ppt = new Properties();

	private static String code_ok;
	private static String msg_ok;

	// 默认错误信息
	static {
		ppt.put("CODE_OK", ERRORCODE_OK);
		ppt.put("MSG_OK", ERRORMSG_OK);
		ppt.put("CODE_0001", ERRORCODE_0001);
		ppt.put("MSG_0001", ERRORMSG_0001);
		ppt.put("CODE_0002", ERRORCODE_0002);
		ppt.put("MSG_0002", ERRORMSG_0002);
		ppt.put("CODE_0003", ERRORCODE_0003);
		ppt.put("MSG_0003", ERRORMSG_0003);
		ppt.put("CODE_0004", ERRORCODE_0004);
		ppt.put("MSG_0004", ERRORMSG_0004);
		ppt.put("CODE_0005", ERRORCODE_0005);
		ppt.put("MSG_0005", ERRORMSG_0005);
		ppt.put("CODE_0006", ERRORCODE_0006);
		ppt.put("MSG_0006", ERRORMSG_0006);
		ppt.put("CODE_0007", ERRORCODE_0007);
		ppt.put("MSG_0007", ERRORMSG_0007);
		ppt.put("CODE_0008", ERRORCODE_0008);
		ppt.put("MSG_0008", ERRORMSG_0008);

		ppt.put("CODE_OK", CODE_OK);
		ppt.put("MSG_OK", MSG_OK);
		ppt.put("MSG_OK_RCV", MSG_OK_RCV);
		ppt.put("CODE_0001", CODE_0001);
		ppt.put("MSG_0001", MSG_0001);
		ppt.put("CODE_0002", CODE_0002);
		ppt.put("MSG_0002", MSG_0002);
		ppt.put("CODE_0003", CODE_0003);
		ppt.put("MSG_0003", MSG_0003);
		ppt.put("CODE_0004", CODE_0004);
		ppt.put("MSG_0004", MSG_0004);
		ppt.put("CODE_0005", CODE_0005);
		ppt.put("MSG_0005", MSG_0005);
		ppt.put("CODE_0006", CODE_0006);
		ppt.put("MSG_0006", MSG_0006);
		ppt.put("CODE_0007", CODE_0007);
		ppt.put("MSG_0007", MSG_0007);
		ppt.put("CODE_0008", CODE_0008);
		ppt.put("MSG_0008", MSG_0008);
		ppt.put("DupTradSn_CODE", DupTradSn_CODE);
		ppt.put("DupTradSn_MSG", DupTradSn_MSG);
		ppt.put("Verify_CODE", Verify_CODE);
		ppt.put("Verify_MSG", Verify_MSG);
		ppt.put("Verify_MSG1", Verify_MSG1);
		ppt.put("Sign_CODE", Sign_CODE);
		ppt.put("Sign_MSG", Sign_MSG);
		ppt.put("NoExist_CODE", NoExist_CODE);
		ppt.put("NoExist_MSG", NoExist_MSG);
	}

	public static String CODE_OK() {
		if (code_ok == null) {
			String ret = (String)ppt.get("CODE_OK");
			code_ok = ret == null ? ERRORCODE_OK : ret;

		}
		return code_ok;
	}

	public static String MSG_OK() {
		if (msg_ok == null) {
			String ret = (String)ppt.get("MSG_OK");
			msg_ok = ret == null ? ERRORMSG_OK : ret;
		}
		return msg_ok;
	}


	public static String get(String key) {
		return ppt.getProperty(key, "");
	}

}
