package com.pingan.b2bic.sign;

import java.util.List;
import java.util.Map;

public interface ISignFactory {
	/**
	 * 创建签名工具
	 *
	 * @param signMode
	 *            签名模式
	 * @param param
	 *            附加参数
	 * @return
	 */
	ISign createSignTool(String signMode, Map param) throws Exception;

	/**
	 * 创建默认签名工具
	 *
	 * @return
	 * @throws Exception
	 */
	ISign createSignTool() throws Exception;

	/**
	 * 取证书列表
	 *
	 * @param signMode
	 *            签名模式
	 * @return
	 * @throws Exception
	 */
	List findCerts(String signMode) throws Exception;

	/**
	 * 创建验签名工具，只支持CFCA软证书
	 * **/
	public ISign createVerifySignTool();

}
