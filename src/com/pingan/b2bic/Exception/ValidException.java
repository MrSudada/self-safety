package com.pingan.b2bic.Exception;


public class ValidException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private String errorCode;

	private String errorMsg;

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public String getErrorMsg() {
		return errorMsg;
	}

	public void setErrorMsg(String errorMsg) {
		this.errorMsg = errorMsg;
	}

	public String getMessage() {
		String s = super.getMessage();
		return s == null ? errorMsg : errorMsg + " " + s;
	}
}
