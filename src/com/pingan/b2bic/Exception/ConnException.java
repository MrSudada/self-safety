package com.pingan.b2bic.Exception;

/**
 * 创建连接异常
 *
 * @author ywb
 *
 */
public class ConnException extends Exception {
	private static final long serialVersionUID = 1L;

	public ConnException() {
		super();
	}

	public ConnException(String message, Throwable cause) {
		super(message, cause);
	}

	public ConnException(String message) {
		super(message);
	}

	public ConnException(Throwable cause) {
		super(cause);
	}



}
