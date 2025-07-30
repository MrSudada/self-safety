package com.pingan.b2bic.sign;


public abstract class AbstractSign implements ISign {
	private String hashAlg = "SHA1";

	public String name(){
		return this.getClass().getSimpleName();
	}

	/**
	 * 先hash再签名，若有特殊请重写该方法
	 * **/
	@Override
	public byte[] hashAndSign(byte[] data) throws Exception {
		//SM2 jar会对原数据进行签名
		byte[] hash = SignUtil.digest(data, hashAlg);
		return sign(hash);
	}

	@Override
	public byte[] hashAndSign(String srcFile) throws Exception {
		byte[] hash = SignUtil.digest(srcFile, hashAlg);
		return sign(hash);
	}

	public boolean hashAndVerify(byte[] src, byte[] signData) throws Exception {
		byte[] hash = SignUtil.digest(src, hashAlg);
		return verify(hash, signData);
	}

	public boolean hashAndVerify(String srcFile, byte[] signData)
			throws Exception {
		byte[] hash = SignUtil.digest(srcFile, hashAlg);
		return verify(hash, signData);
	}

	@Override
	public String getHashAlg() {
		return hashAlg;
	}

	@Override
	public void setHashAlg(String hashAlg) {
		this.hashAlg = hashAlg;
	}
}
