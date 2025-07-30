package com.pingan.b2bic.sign;


public interface ISign {
	/**
	 * 名称
	 *
	 * @return
	 */
	String name();

	/**
	 * 返回hash算法
	 */
	String getHashAlg();

	/**
	 * 设置hash算法
	 */
	void setHashAlg(String hashAlg);

	/**
	 * 获取公钥证书
	 *
	 * @return
	 * @throws Exception
	 */
	byte[] getCert() throws Exception;

	/**
	 * 签名
	 *
	 * @param src
	 *            待签名数据
	 * @return 签名后数据
	 * @throws Exception
	 */
	byte[] sign(byte[] hash) throws Exception;

	/**
	 * 计算Hash值后签名
	 *
	 * @param src
	 * @return
	 * @throws Exception
	 */
	byte[] hashAndSign(byte[] src) throws Exception;

	/**
	 * 文件签名
	 *
	 * @param srcFile
	 * @return
	 * @throws Exception
	 */
	byte[] hashAndSign(String srcFile) throws Exception;

	/**
	 * 验签名
	 *
	 * @param hash
	 *            源数据
	 * @param signData
	 *            签名值
	 * @return
	 * @throws Exception
	 */
	boolean verify(byte[] hash, byte[] signData) throws Exception;

	/**
	 * 验签名，先计算Hash值
	 *
	 * @param src
	 * @param signData
	 * @return
	 * @throws Exception
	 */
	boolean hashAndVerify(byte[] src, byte[] signData) throws Exception;

	/**
	 * 文件验签名，先计算Hash值
	 *
	 * @param srcFile
	 * @return
	 * @throws Exception
	 */
	boolean hashAndVerify(String srcFile, byte[] signData)
			throws Exception;

	/**
	 * 获取证书主体DN
	 *
	 * @return
	 */
	String getSubjectDN() throws Exception;

}
