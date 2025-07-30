package com.pingan.b2bic.sign;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.zip.*;
import java.util.*;

/**
 * 签名工具类
 *
 * @author ywb
 *
 */
public class SignUtil {
	private static final int BUFFSIZE = 8096;

	public static final String ALG = "DesEde/CBC/PKCS5Padding";
	public static final String keySpec="DesEde";

	/** 默认初始向量 */
	private static byte[] DEFAULT_IV = new byte[] { 0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08 };

	/**
	 * 计算文件摘要
	 *
	 * @param srcFile
	 * @param hashAlg
	 * @return
	 * @throws Exception
	 */
	public static byte[] digest(String srcFile, String hashAlg)
			throws Exception {
		MessageDigest md = MessageDigest.getInstance(hashAlg);
		byte[] buffer = new byte[BUFFSIZE];
		InputStream ins = null;
		int count = 0;
		try {
			ins = new BufferedInputStream(new FileInputStream(srcFile));
			while ((count = ins.read(buffer)) > 0) {
				md.update(buffer, 0, count);
			}
			byte[] digest = md.digest();
			return digest;
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
		}
	}

	/**
	 * 计算数据摘要
	 *
	 * @param data
	 * @param hashAlg
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] digest(byte[] data, String hashAlg)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(hashAlg);
		byte[] ret = md.digest(data);
		return ret;
	}

	/**
	 * 文件加密
	 *
	 * @param srcFile
	 *            源文件
	 * @param encFile
	 *            加密后文件
	 * @throws Exception
	 *
	 * @return 文件加密密码base64值
	 */
	public static String encrypt(String srcFile, String encFile) throws Exception {
		byte[] bivSpec=null;
		//生成文件随机密码
		Random random = new SecureRandom();
		byte[] bkey = new byte[24];
		random.nextBytes(bkey);

		SecretKeySpec key = new SecretKeySpec(bkey, keySpec);
		Cipher cipher = Cipher.getInstance(ALG);
		if (bivSpec == null) {
			bivSpec = DEFAULT_IV;
		}
		IvParameterSpec ivSpec = new IvParameterSpec(bivSpec);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		createParentDir(encFile, "文件加密失败。");
		InputStream ins = null;
		OutputStream outs = null;
		try {
			ins = new BufferedInputStream(new FileInputStream(srcFile));
			outs = new CipherOutputStream(new FileOutputStream(encFile), cipher);
			byte[] buf = new byte[BUFFSIZE];
			int count = -1;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}

			return new String(com.pingan.b2bic.Util.Base64.encode(bkey));
		}
	}

	/**
	 * 文件解密
	 *
	 * @param srcFile
	 *            源文件
	 * @param dstFile
	 *            解密后文件
	 * @param filePass
	 *            文件密码
	 * @throws Exception
	 */
	public static void decrypt(String srcFile, String dstFile, String filePass) throws Exception {
		byte[] bivSpec=null;
		byte [] bkey = com.pingan.b2bic.Util.Base64.decode(filePass.getBytes());
		SecretKeySpec key = new SecretKeySpec(bkey, keySpec);
		Cipher cipher = Cipher.getInstance(ALG);
		if (bivSpec == null) {
			bivSpec = DEFAULT_IV;
		}
		IvParameterSpec ivSpec = new IvParameterSpec(bivSpec);
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		createParentDir(dstFile, "文件解密失败。");
		InputStream ins = null;
		OutputStream outs = null;
		try {
			ins = new CipherInputStream(new BufferedInputStream(
					new FileInputStream(srcFile)), cipher);
			outs = new BufferedOutputStream(new FileOutputStream(dstFile));
			byte[] buf = new byte[BUFFSIZE];
			int count = -1;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}
		}
	}

	/**
	 * 文件压缩
	 * <p>
	 * zip格式
	 *
	 * @param srcFile
	 * @param dstFile
	 */
	public static void compress(String srcFile, String dstFile)
			throws Exception {
		createParentDir(dstFile, "文件压缩失败。");
		InputStream ins = null;
		ZipOutputStream outs = null;
		try {
			outs = new ZipOutputStream(new FileOutputStream(new File(dstFile)));
			ins = new BufferedInputStream(new FileInputStream(srcFile),
					BUFFSIZE);
			byte[] buf = new byte[BUFFSIZE];
			ZipEntry entry = new ZipEntry(new File(srcFile).getName());
			outs.putNextEntry(new ZipEntry(entry));
			int count = 0;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
			outs.closeEntry();
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}
		}
	}

	/**
	 * 文件压缩
	 *
	 * @param srcFile
	 * @param destFile
	 */
	public static void compress_gzip(String srcFile, String dstFile)
			throws Exception {
		createParentDir(dstFile, "文件压缩失败。");
		InputStream ins = null;
		OutputStream outs = null;
		try {
			ins = new BufferedInputStream(new FileInputStream(srcFile));
			outs = new GZIPOutputStream(new FileOutputStream(dstFile));
			byte[] buf = new byte[BUFFSIZE];
			int count = -1;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}
		}
	}

	/**
	 * 文件解压缩
	 * <p>
	 * Zip格式，只允许包含一个文件（不允许有文件夹）
	 *
	 * @param srcFile
	 * @param dstFile
	 */
	public static void uncompress(String srcFile, String dstFile)
			throws Exception {
		createParentDir(dstFile, "文件解压缩失败。");
		ZipFile zfile = null;
		OutputStream outs = null;
		try {
			zfile = new ZipFile(srcFile);
			Enumeration e = zfile.entries();
			if (!e.hasMoreElements()) {
				throw new Exception("压缩包条目为空");
			}
			ZipEntry entry = (ZipEntry) (e.nextElement());
			if (e.hasMoreElements()) {
				throw new Exception("压缩包中包含多个文件或文件夹");
			}
			InputStream ins = zfile.getInputStream(entry);
			outs = new BufferedOutputStream(new FileOutputStream(dstFile));
			byte[] buf = new byte[BUFFSIZE];
			int count = -1;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
			ins.close();
		} finally {
			if (zfile != null) {
				try {
					zfile.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}
		}
	}

	public static void uncompress_gzip(String srcFile, String dstFile)
			throws Exception {
		createParentDir(dstFile, "文件解压缩失败。");
		InputStream ins = null;
		OutputStream outs = null;
		try {
			ins = new GZIPInputStream(new BufferedInputStream(
					new FileInputStream(srcFile)));
			outs = new BufferedOutputStream(new FileOutputStream(dstFile));
			byte[] buf = new byte[BUFFSIZE];
			int count = -1;
			while ((count = ins.read(buf)) != -1) {
				outs.write(buf, 0, count);
				outs.flush();
			}
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (Exception e) {
				}
			}
			if (outs != null) {
				try {
					outs.close();
				} catch (Exception e) {
				}
			}
		}
	}

	/**
	 * 创建父目录
	 *
	 * @param filepath
	 * @param errMsg
	 * @throws Exception
	 */
	private static void createParentDir(String filepath, String errMsg)
			throws Exception {
		File f = new File(filepath);
		File fdir = f.getParentFile();
		if (fdir != null && !fdir.exists()) {
			if (!fdir.mkdirs()) {
				throw new Exception(errMsg + "创建目录失败：" + fdir.getAbsolutePath());
			}
		}
	}

	/**
	 * 数据加密
	 *
	 * @param data
	 * @param bkey
	 * @param algorithm
	 * @param keySpec
	 * @param bivSpec
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] bkey, String algorithm,
                                 String keySpec, byte[] bivSpec) throws Exception {
		SecretKeySpec key = new SecretKeySpec(bkey, keySpec);
		Cipher c = Cipher.getInstance(algorithm);
		if (bivSpec == null) {
			bivSpec = DEFAULT_IV;
		}
		IvParameterSpec ivSpec = new IvParameterSpec(bivSpec);
		c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		return c.doFinal(data);
	}

	/**
	 * 数据解密
	 *
	 * @param data
	 * @param bkey
	 * @param algorithm
	 * @param keySpec
	 * @param bivSpec
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] bkey, String algorithm,
                                 String keySpec, byte[] bivSpec) throws Exception {
		SecretKeySpec key = new SecretKeySpec(bkey, keySpec);
		Cipher c = Cipher.getInstance(algorithm);
		if (bivSpec == null) {
			bivSpec = DEFAULT_IV;
		}
		IvParameterSpec ivSpec = new IvParameterSpec(bivSpec);
		c.init(Cipher.DECRYPT_MODE, key, ivSpec);
		return c.doFinal(data);
	}
}
