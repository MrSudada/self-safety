package com.pingan.b2bic.sign.usbkey.winapi;

public class LastErrorException extends RuntimeException {
	private int code;
	
	private static final long serialVersionUID = 1L;
	
	public LastErrorException(int code, String errMsg) {
		super(errMsg);
		this.code = code;
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}
	
}
