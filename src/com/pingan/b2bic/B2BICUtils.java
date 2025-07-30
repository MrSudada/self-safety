package com.pingan.b2bic;

import com.jcraft.jsch.*;
import com.pingan.b2bic.Config.DesReader;
import com.pingan.b2bic.Config.FtpConfig;
import com.pingan.b2bic.Exception.CodeAndMsgException;
import com.pingan.b2bic.Exception.InvalidDataException;
import com.pingan.b2bic.Http.HttpRspVo;
import com.pingan.b2bic.sign.Config;
import com.pingan.b2bic.sign.SignFactory;
import com.pingan.b2bic.sign.ISign;
import com.pingan.b2bic.Util.Service;
import com.pingan.b2bic.Util.YQUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.io.*;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static com.pingan.b2bic.Util.StringTool.fillChar;
import static com.pingan.b2bic.Util.YQUtil.*;

/**
 *      <h1>SDK说明-version.20250410</h1>
 *      <ol>
 *      <li>SDK工具类入口方法，调用本类sendTobank静态方法进行输入校验，和银行通讯，并实时返回结果。</li>
 *      <li>与银行服务端之间采用HTTPS加密传输，交易数据采用客户证书签名，同时服务端验证数据一致性和客户的身份，可以确保通讯传输的安全，交易数据无法被篡改。</li>
 *      <li>与银行通讯时，验证服务端证书公钥，可以确保银行的身份，以防假冒的服务提供者。</li>
 *      <li>最大支持50个文件证书签名并发。</li>
 *      <li>若校验模板文件不存在，不进行校验，直接转发。</li>
 *      <li>暂只接受Map报文体，并返回Map报文体,不支持携带附件。</li>
 *      <li>暂只支持A001规范封装报文。</li>
 *      <li>与银行上行通讯暂只支持HTTPS协议。</li>
 *      <li>暂不支持FTP服务。</li>
 *      </ol>
 *      <hr>
 *      <h1>依赖五个文件夹</h1>
 *      <ol>
 *      <li>配置文件，程序目录configuration文件夹下。</li>
 *      <li>日志文件，程序目录log文件夹下。</li>
 *      <li>证书文件，程序目录cert文件夹下。</li>
 *      <li>主包及依赖包，程序目录lib文件夹下。</li>
 *      <li>校验模板文件，程序目录template文件夹下(非必须配置)。</li>
 *      <li>国密证书签名日志文件，程序目录signstore文件夹下。</li>
 *      </ol>
 *      <hr>
 *      <h1>配置文件说明</h1>
 *      <h2>日志配置文件，log4j.xml</h2>
 *      <ol>
 *      <li>level value="debug"            ---- 默认日志打印级别，日志级别划分为：debug、info、warn、error、fatal五个级别，debug级别日志输出最详细，fatal级别日志输出最简略。</li>
 *      <li>com.pingan.b2bic.B2BICUtils    ---- 该节点需保持打开，保持info级别。</li>
 *      <li>com.pingan.b2bic.Util          ---- 该节点需保持打开，保持info级别。</li>
 *      <li>其余节点配置建议保持默认。</li>
 *      <li>按天生成，API使用如有问题请提供当天日志文件。</li>
 *      </ol>
 *      <h2>签名配置文件，cfgsign.xml</h2>
 *      <ol>
 *      <li>signMode                       ---- 签名模式，支持RSA_SOFT文件证书和SM2_SOFT国密文件证书。</li>
 *      <li>pfxPath                        ---- 证书路径。</li>
 *      <li>pfxPwd                         ---- 证书密码，密码需要使用B2BICUtils.passwordWrite(String inputKey) 生成获取密文。</li>
 *      <li>certDn                         ---- 证书DN,无需配置</li>
 *      <li>caCertPath                     ---- ca证书路径，指向工作目录cert文件夹ebankprd.p7b文件。</li>
 *      <li>isUpSignAllTx                  ---- 全部交易签名，保持默认。</li>
 *      <li>其他请保持默认。</li>
 *      </ol>
 *      <h2>国密证书签名配置文件，netsign.properties</h2>
 *      <ol>
 *      <li>若为国密证书，请同时修改此配置文件</li>
 *      <li>pfx0  ---- 证书文件名称，相对cert目录</li>
 *      <li>passwordpfx0  ---- 证书密码，此处配置明文</li>
 *      </ol>
 *      <h2>上行配置文件，cfgbank.xml</h2>
 *      <ol>
 *      <li>ips                            ---- 上行交易行方服务器IP地址，行方提供。</li>
 *      <li>ports                              ----银行服务端端口，行方提供。</li>
 *      <li>测试环境：域名my-uat1.orangebank.com.cn(218.17.132.166)，端口462/466，建议配置域名+端口。</li>
 *      <li>生产环境：域名ebank.sdb.com.cn	(219.133.104.74、210.21.217.74)，端口469，建议配置域名+端口。</li>
 *      <li>其他请保持默认。</li>
 *      </ol>
 *      <hr>
 *      <h1>主jar包：middleware.jar</h1>
 *      <h2>依赖包及版本</h2>
 *      <ol>
 *      <li>oracle jdk 1.6+ or openJDK 1.6+</li>
 *      <li>dom4j-1.6.1.jar</li>
 *      <li>commons-logging-1.1.1.jar</li>
 *      <li>CFCACertKitJS.jar</li>
 *      <li>PKIBASE.jar</li>
 *      <li>bcmail-jdk14-146.jar</li>
 *      <li>bcprov-jdk14-146.jar</li>
 *      <li>ISFJ_v2_0_139_15_BAISC_JDK15.jar</li>
 *      <li>com.sun.jna.jar</li>
 *      <li>org_apache_commons_configuration.jar</li>
 *      <li>edu_emory_mathcs_backport_java_util_concurrent.jar</li>
 *      <li>org_apache_commons_httpclient.jar</li>
 *      <li>netsign18.jar</li>
 *      <li>netsignderutil.jar</li>
 *      <li>infoseckeytool.jar</li>
 *      </ol>
 *
 * @author guolitao
 */
public class B2BICUtils {

    private static final Log log = LogFactory.getLog(B2BICUtils.class);

    public static final String TRAN_TYPE_DOWNLOAD = "0";
    public static final String TRAN_TYPE_UPLOAD = "1";
    /***
     * 使用指定的证书就行签名发送，适用多个客户多份证书实时切换的场景
     * @param systemId  银行业务ID
     * @param encoding  报文编码01-GBK;02-UTF-8(推荐)
     * @param trancode  交易代码
     * @param yqdm      客户代码
     * @param reqMsg    请求报文头备注-可以空
     * @param pfxPath   证书路径
     * @param pfxPwd    证书密码
     * @param signMode    证书类型:RSA_SOFT/SM2_SOFT
     * @param body      为输入任意格式的报文体
     * @return          包含报文头（一定返回，键为head，值为Map）和报文体（错误不返回，键为body，值为报文体字符串）
     * */
    public static Map sendTobank(String body, String systemId, String encoding, String trancode,
                                 String yqdm, String reqMsg, String pfxPath, String pfxPwd, String signMode) {

        Service service = Service.getInstance();
        String threadId = service.nextSn();
        long timeStart=System.currentTimeMillis();

        log.info("["+threadId+"]"+"Call interface start..." );
        log.info("["+threadId+"]"+"trancode= " + trancode);
        log.info("["+threadId+"]"+"yqdm = " + yqdm);
        log.info("["+threadId+"]"+"System Id= " + systemId);
        log.info("["+threadId+"]"+"Charseset= " + encoding);


        //encoding不合法强制置为01 GBK
        if(encoding==null||encoding.equals("")||encoding.length()!=2){encoding="01";}
        String encode = "GBK";
        if (encoding.equals("02")){
            encode="UTF-8";
        } else if (encoding.equals("03")) {
            encode="unicode";
        } else if (encoding.equals("04")) {
            encode="iso-8859-1";
        }
        if(encode.equals("GBK")){encoding="01";}

        //systemId不合法强制置为01 银企直连
        if(systemId==null||systemId.equals("")||systemId.length()!=2){systemId = "01";}

        //最终返回Map，一定有mapHead，不成功无mapbody
        Map result = new HashMap();
        Map mapHead = new HashMap();
        //默认返回错误码和错误信息
        mapHead.put("errCode","-1");
        mapHead.put("errMsg","Return Body Null,Check config.properties");

        if(body.isEmpty()){
            log.error("Request body is empty，Please check");
            mapHead.put("errCode","-2");
            mapHead.put("errMsg","Request Body Null");
            result.put("head",mapHead);
            return result;
        }

        boolean checkResult = false;
        try {

            String xmlFile = body;

            String resquest = asemblyPackets(systemId,encoding,encode,fillString(yqdm,20,encode),fillString(trancode,6,encode),reqMsg,xmlFile);

            // 签名
            ISign signTool = new SignFactory().createSignToolWithPath(pfxPath,pfxPwd,signMode);
            log.info("signTool=" + signTool.hashCode());
            byte[] src = signTool.hashAndSign(resquest.getBytes(encode));

            String signData = new String(src,encode);
            String signDataLength = String.valueOf(signData.getBytes(encode).length);

            log.info("["+threadId+"]signData=" + signData);

            HttpRspVo rspVo = send((resquest + fillChar(signDataLength, '0', 6, true) + signData).getBytes(encode),encode,createReqestStream());

            String resHead = new String(rspVo.getBody(),0,222,encode);
            log.info( "["+threadId+"]response header[" + resHead+"]");
            if(resHead.trim().equals("")){
                throw new SocketException();
            }
            mapHead = head2Map(resHead.getBytes(encode),encode);
            String resBody = new String(rspVo.getBody(),222,rspVo.getBody().length-222,encode);

            long timeEnd=System.currentTimeMillis();

            log.info("["+threadId+"]cost["+(timeEnd-timeStart)+"]ms,response body [" + resBody+"]");
            result.put("body",resBody);
        }
        catch (DocumentException e){
            log.error(  "["+threadId+"]Template acquisition failed..." + e.getMessage());
            mapHead.put("errCode","-4");
            mapHead.put("errMsg","Trancode Error");
        }
        catch (UnsupportedEncodingException e){
            log.error("["+threadId+"]Encoding is unsupported..." + e.getMessage());
            mapHead.put("errCode","-5");
            mapHead.put("errMsg","Encode Error");
        }
        catch (NullPointerException e){
            log.error("["+threadId+"]Response body is empty,pleace check parameter...");
        }
        catch (ConnectException e){
            log.error("["+threadId+"]connection exception...");
            mapHead.put("errCode","-6");
            mapHead.put("errMsg","Connection Refused");
        }
        catch (SocketException e){
            log.error("["+threadId+"]Protocol connection exception, please convert protocol request...");
            mapHead.put("errCode","-7");
            mapHead.put("errMsg","Protocol Error");
        }
        catch (InvalidDataException e){
            log.error("["+threadId+"]Verification failed...");
            mapHead.put("errCode","-8");
            mapHead.put("errMsg",e.getMessage());
        }
        catch (FileNotFoundException e){
            log.error("["+threadId+"]Fail to Read Doc...");
            mapHead.put("errCode","-9");
            mapHead.put("errMsg",e.getMessage());
        }
        catch (UnknownHostException e){
            log.error("["+threadId+"]Failed to get client IP and MAC address...");
            mapHead.put("errCode","-10");
            mapHead.put("errMsg",e.getMessage());
        }
        catch(CodeAndMsgException e) {
            log.error("["+threadId+"]CodeAndMsgException..."+e.getErrorCode()+e.getErrorMsg()+e.getMessage());
            throw e;
        }
        catch (Exception e){
            log.error("["+threadId+"]System error..." + e.getMessage() + "\n");
            mapHead.put("errCode","-11");
            mapHead.put("errMsg","System Failed");
        }
        result.put("head",mapHead);
        return result;
    }




    /**
     * 银行sftp文件上传和下载，并返回文件随机密码（该密码用于银行业务接口上送）。
     * 文件传输前先生成随机密码，压缩后加密，以确保文件不被修改。需依次按如下3个步骤完成：
     * 1. 调用SignUtil.compress(srcFile, zipFile) 压缩文件，在本地文件目录下会生成.zip文件，需要本地目录的写入权限。
     * 2. 调用SignUtil.encrypt(zipFile, encFile) 加密压缩后的文件，本地目录会生成.enc结尾的文件。
     * 3. 调用sftpTransfer方法完成文件传输。
     *
     * @param tranType 文件传输方式B2BICUtils.TRAN_TYPE_UPLOAD 上传;B2BICUtils.TRAN_TYPE_DOWNLOAD下载;
     * @param remoteFileName 远端文件名称，注意不能以/开头，不能包含路径（文件路径配置在cfgbank.xml中 ftpServers.defaultDir）。
     * @param localPath 本地文件路径
     * @param localFileName 本地文件名称
     * **/
    public static void sftpTransfer(String tranType,
                             String remoteFileName,
                             String localPath,String localFileName) throws Exception {
        Service service = Service.getInstance();
        String threadId = service.nextSn();
        long timeStart = System.currentTimeMillis();

        FtpConfig bankFtpConfig = Config.getInstance().getBankftpCfg();
        String userName=bankFtpConfig.getFtpname();
        String serverIp = bankFtpConfig.getHostname();
        int port = bankFtpConfig.getPort();
        String remotePath =bankFtpConfig.getDefaultDir();
        log.info("["+threadId+"]"+"sftpTransfer start... tranType[0-down;1-up]:"+tranType+","+ userName+"@"+serverIp+":"+port+",remotePath["+remotePath+"]remoteFileName["+remoteFileName+"]localPath["+localPath+"]localFileName["+localFileName+"]" );

        // 新增重试策略及超时时间控制
        int exeCount = 1;
        int timeout = 10000;
        ChannelSftp sftp = null;
        Session sshSession = null;
        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            for (int i = 0; i < exeCount; i++) {
                try {
                    JSch jsch = new JSch();
                    sshSession = jsch.getSession(userName,serverIp ,port );

                    sshSession.setPassword(bankFtpConfig.getFtppwd());
                    Properties sshConfig = new Properties();
                    sshConfig.put("StrictHostKeyChecking", "no");
                    sshSession.setConfig(sshConfig);
                    sshSession.connect();
                    Channel channel = sshSession.openChannel("sftp");
                    channel.connect(timeout);

                    sftp = (ChannelSftp) channel;
                    sftp.setFilenameEncoding(bankFtpConfig.getEncoding());

                    if (tranType.equals(TRAN_TYPE_UPLOAD)) {
                        //若为根目录，先切换目录; 防止在当前目录创建目录
                        if (remotePath.startsWith("/")) {
                            sftp.cd("/");
                        }
                        //若目录不存在则创建目录  ，并进入最终目录
                        YQUtil.createDir(remotePath, sftp);
                        File file = new File(localPath + "/" + localFileName);
                        fis = new FileInputStream(file);
                        sftp.put(fis, remoteFileName);
                    } else if (tranType.equals(TRAN_TYPE_DOWNLOAD)) {
                        sftp.cd(remotePath);
                        File file = new File(localPath + "/" + localFileName);
                        fos = new FileOutputStream(file);
                        sftp.get(remoteFileName, fos);
                    }
                    log.warn("["+threadId+"]sftp transfer success.tranType[0-down;1-up]:" + tranType);
                    // return之前要调用setSuccessStatus();
                    break;
                } catch (Exception ex) {
                    if (i < exeCount - 1) {
                        log.warn("sftp端点异常，进行重试"+serverIp+userName, ex);
                        try {
                            Thread.sleep(1000);
                        } catch (Exception exp) {
                            throw new Exception("YQ9999-sftp file exp error",exp);
                        }
                    } else {
                        throw ex;
                    }
                }
            }
        } catch (JSchException jsche) {
            log.error(jsche);
            throw new Exception("YQ999-sftp file transfer error: " + userName+"@"+serverIp+":"+port, jsche);
        } catch(SftpException sftpe) {
            log.error("YQ9999" + "|" + "sftp file transfer error: "+remoteFileName,sftpe);
            throw new Exception("YQ999-sftp file transfer error: " + remoteFileName, sftpe);
        } catch(Exception ioe) {
            log.error( "sftp file io error: " + remoteFileName, ioe);
            throw new Exception("YQ999-sftp file io error: " + remoteFileName, ioe);
        } finally {
            log.warn( "["+threadId+"]"+String.format("sftp file  tranType:%s ,remotePath:%s", tranType, remotePath));
            if (sftp != null) {
                sftp.disconnect();
            }
            if (sshSession != null) {
                sshSession.disconnect();
            }
            if(fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if(fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }


    /***
     * 使用默认配置证书就行签名发送
     * @param systemId  银行业务ID
     * @param encoding  报文编码01-GBK;02-UTF-8(推荐)
     * @param trancode  交易代码
     * @param yqdm      客户代码
     * @param reqMsg    请求报文头备注-可以空
     * @param body      为输入任意格式的报文体
     * @return          包含报文头（一定返回，键为head，值为Map）和报文体（错误不返回，键为body，值为报文体字符串）
     * */
    public static Map sendTobank(String body, String systemId, String encoding, String trancode,
                                 String yqdm, String reqMsg) {

        Service service = Service.getInstance();
        String threadId = service.nextSn();
        long timeStart = System.currentTimeMillis();
        log.info("["+threadId+"]"+"Call interface start..." );
        log.info("["+threadId+"]"+"trancode= " + trancode);
        log.info("["+threadId+"]"+"yqdm = " + yqdm);
        log.info("["+threadId+"]"+"System Id= " + systemId);
        log.info("["+threadId+"]"+"Charseset= " + encoding);


        //encoding不合法强制置为01 GBK
        if(encoding==null||encoding.equals("")||encoding.length()!=2){encoding="01";}
        String encode = "GBK";
        if (encoding.equals("02")){
            encode="UTF-8";
        } else if (encoding.equals("03")) {
            encode="unicode";
        } else if (encoding.equals("04")) {
            encode="iso-8859-1";
        }
        if(encode.equals("GBK")){encoding="01";}

        //systemId不合法强制置为01 银企直连
        if(systemId==null||systemId.equals("")||systemId.length()!=2){systemId = "01";}

        //最终返回Map，一定有mapHead，不成功无mapbody
        Map result = new HashMap();
        Map mapHead = new HashMap();
        //默认返回错误码和错误信息
        mapHead.put("errCode","-1");
        mapHead.put("errMsg","Return Body Null,Check config.properties");

        if(body.isEmpty()){
            log.error("Request body is empty，Please check");
            mapHead.put("errCode","-2");
            mapHead.put("errMsg","Request Body Null");
            result.put("head",mapHead);
            return result;
        }

        boolean checkResult = false;
        try {

            String xmlFile = body;

            String resquest = asemblyPackets(systemId,encoding,encode,fillString(yqdm,20,encode),fillString(trancode,6,encode),reqMsg,xmlFile);

            // 签名
            ISign signTool = new SignFactory().createSignTool();
            log.info("["+threadId+"]signTool=" + signTool.hashCode());
            byte[] src = signTool.hashAndSign(resquest.getBytes(encode));

            String signData = new String(src,encode);
            String signDataLength = String.valueOf(signData.getBytes(encode).length);

            log.info("["+threadId+"]signData=" + signData);

            HttpRspVo rspVo = send((resquest + fillChar(signDataLength, '0', 6, true) + signData).getBytes(encode),encode,createReqestStream());

            String resHead = new String(rspVo.getBody(),0,222,encode);
            log.info( "["+threadId+"]response header [" + resHead+"]");
            if(resHead.trim().equals("")){
                throw new SocketException();
            }
            mapHead = head2Map(resHead.getBytes(encode),encode);
            String resBody = new String(rspVo.getBody(),222,rspVo.getBody().length-222,encode);

            long timeEnd=System.currentTimeMillis();
            log.info("["+threadId+"]cost["+(timeEnd-timeStart)+"]ms,response body [" + resBody+"]");
            result.put("body",resBody);
        }
        catch (DocumentException e){
            log.error(  "["+threadId+"]Template acquisition failed..." + e.getMessage());
            mapHead.put("errCode","-4");
            mapHead.put("errMsg","Trancode Error");
        }
        catch (UnsupportedEncodingException e){
            log.error("["+threadId+"]Encoding is unsupported..." + e.getMessage());
            mapHead.put("errCode","-5");
            mapHead.put("errMsg","Encode Error");
        }
        catch (NullPointerException e){
            log.error("["+threadId+"]Response body is empty,pleace check parameter...");
        }
        catch (ConnectException e){
            log.error("["+threadId+"]connection exception...");
            mapHead.put("errCode","-6");
            mapHead.put("errMsg","Connection Refused");
        }
        catch (SocketException e){
            log.error("["+threadId+"]Protocol connection exception, please convert protocol request...");
            mapHead.put("errCode","-7");
            mapHead.put("errMsg","Protocol Error");
        }
        catch (InvalidDataException e){
            log.error("["+threadId+"]Verification failed...");
            mapHead.put("errCode","-8");
            mapHead.put("errMsg",e.getMessage());
        }
        catch (FileNotFoundException e){
            log.error("["+threadId+"]Fail to Read Doc...");
            mapHead.put("errCode","-9");
            mapHead.put("errMsg",e.getMessage());
        }
        catch (UnknownHostException e){
            log.error("["+threadId+"]Failed to get client IP and MAC address...");
            mapHead.put("errCode","-10");
            mapHead.put("errMsg",e.getMessage());
        }
        catch(CodeAndMsgException e) {
            log.error("["+threadId+"]CodeAndMsgException..."+e.getErrorCode()+e.getErrorMsg()+e.getMessage());
            throw e;
        }
        catch (Exception e){
            log.error("["+threadId+"]System error..." + e.getMessage() + "\n");
            mapHead.put("errCode","-11");
            mapHead.put("errMsg","System Failed");
        }
        result.put("head",mapHead);
        return result;
    }

    /***
     * 用于验证银行请求客户时的请求签名是否合法
     * 银行证书公钥配置在cfgsign.xml中bankCertDN
     * 若证书非法，则抛出异常。
     * */
    public static void bankInSignVerify(final byte[] bankIn, String encoding) throws Exception {
        String resHead = new String(bankIn,0,222,encoding);

        Map mapHead = head2Map(resHead.getBytes(encoding),encoding);
        log.info("bankIn.head:"+mapHead);

        byte[] signSrc = new byte[222+Integer.parseInt((String) mapHead.get("dataBodyLen"))];
        System.arraycopy(bankIn,0,signSrc,0,signSrc.length);

        byte[] signlengthByte= new byte[6];
        System.arraycopy(bankIn,signSrc.length,signlengthByte,0,signlengthByte.length);
        int signLength = Integer.parseInt(new String(signlengthByte));
        log.info("bankIn.signlength:"+signLength);

        byte[] signContent = new byte[signLength];
        System.arraycopy(bankIn,signSrc.length+signlengthByte.length,signContent,0,signContent.length);
        log.info("bankIn.signContent:"+new String(signContent));


        ISign signTool = new SignFactory().createVerifySignTool();
        boolean ret = false;
        try {
            ret = signTool.hashAndVerify(signSrc, signContent);
        } catch (Exception e) {
            log.error("验签名异常:", e);
            ret = false;
        }
        if(!ret){
            throw new Exception("YQ9993-下行请求签名验证非法");
        }


    }


    public static String sign(byte[] src, String encoding, String pfxPath, String pfxPwd, String signMode) throws Exception {
        ISign signTool = (new SignFactory()).createSignToolWithPath(pfxPath, pfxPwd,signMode);
        log.info("signTool=" + signTool.hashCode());
        byte[] srcAfterSign = signTool.hashAndSign(src);
        return new String(srcAfterSign, encoding);
    }

    /**
     * @author            Anzhi
     * @param mapCheck    待校验Map
     * @param trancode    交易代码
     * @return            boolean
     * @throws DocumentException         XML转换到Document失败时，抛出此异常
     * @throws IllegalArgumentException  校验失败时抛出此异常
     * @since             2018/4/27
     */
    private static boolean getTemplate(Map mapCheck, String trancode) throws DocumentException,InvalidDataException {

        //校验模板,也用Map保存
        String file = System.getProperty("user.dir") + File.separator + "template" + File.separator +trancode + ".xml";
        log.info("Loading template file......" + file);
        InputStream inputStream =null;
        try {
            inputStream = new FileInputStream(file);
        } catch (FileNotFoundException e){
            log.info("The template file does not exist, and it will be forwarded to the bank directly..." );
            return true;
        }
        SAXReader reader = new SAXReader();
        Document document = reader.read(inputStream);
        log.info("template content is: " + document.asXML());
        List<Element> listTemplate = document.getRootElement().elements();
        return forwardValidate(mapCheck, listTemplate);
    }

    /**
     * @author              Anzhi
     * @param mapCheck      待校验Map
     * @param listTemplate  模板List
     * @return              void
     * @exception
     * @since               2018/4/27
     */
    private static boolean forwardValidate(Map mapCheck, List<Element> listTemplate) throws InvalidDataException {

        log.info("Pre check start");
        for (Element e : listTemplate) {
            //字段域下嵌套字段
            if(e.content().size()!=0){
                log.info(e.attributeValue("id") + "There is a secondary menu, enter the nested loop");
                //按照map list map的数据结构 嵌套执行
                List<Map> listTem = (List) mapCheck.get(e.attributeValue("id"));
                for (Map mapChe : listTem) {
                    forwardValidate((mapChe) ,e.elements());
                }
            }
            //获取所有的校验参数
            List<Attribute> attributes = e.attributes();
            Map mapAttributes = new HashMap();
            //用map保存所有校验参数
            for (Attribute attribute : attributes) {
                mapAttributes.put(attribute.getName(), attribute.getValue());
                log.info("The field parameter is " + attribute.getName()+" value is " + attribute.getValue());
            }
            //实际校验方法  map待校验文件 map1所有校验参数
            validate(mapCheck, mapAttributes);
        }
        return true;
    }

    /**
     * @author             Anzhi
     * @param xmlMap       待校验Map
     * @param templateMap  模板Map
     * @return             boolean
     * @throws
     * @since              2018/4/27
     */
    private static boolean validate(Map xmlMap, Map templateMap) throws InvalidDataException {

        log.info("check start");
        boolean result = false;
        //字段名称
        String id = (String) templateMap.get("id");
        //字段值
        String value = (String) xmlMap.get(id);
        log.info("check field: " + id);
        //校验必输字段
        if (templateMap.get("must").equals("true")) {
            if (!xmlMap.containsKey(id)) {
                log.info(id + "It is a required field, please add");
                throw new InvalidDataException("formatError!The \""+id+"\" must input");
            }
        }
        //必输字段或者非必输但有值，作校验
        if(templateMap.get("must").equals("true")||xmlMap.containsKey(id)) {
            if (templateMap.containsKey("enumeration")) {
                boolean enumResult = false;
                String[] strings = templateMap.get("enumeration").toString().split("\\|");
                for (String str : strings) {
                    if (str.equals(xmlMap.get(id))) {
                        enumResult = true;
                        break;
                    }
                }
                if (enumResult == false) {
                    log.info(id + "value should be one of" + templateMap.get("enumeration").toString() + ",please check！");
                    throw new InvalidDataException("formatError!The \"" + id + "\" must in " + templateMap.get("enumeration").toString());
                }
            }

            //校验数据类型  "X":字母数字;"9":数字;"A":大写字母（缺省值为X）
            String type = (String) templateMap.get("dataType");
            if ("9".equals(type)) {
                if (value.indexOf(".") == -1) {
                    for (int i = 0; i < value.length(); i++) {
                        char c = value.charAt(i);
                        if (!('0' <= c && c <= '9' || " ".indexOf(c) != -1))
                            throw new InvalidDataException("formatError!The \"" + value + "\" contains " + c + "which is not between \"0\" and \"9\" or [" + " " + "] while the type is \"9\".");
                    }
                }
            } else if ("A".equals(type)) {
                for (int i = 0; i < value.length(); i++) {
                    char c = value.charAt(i);
                    if (!('A' <= c && c <= 'Z' || " ".indexOf(c) != -1))
                        throw new InvalidDataException("formatError!The \"" + value + "\" contains " + c + "which is not between \"A\" and \"Z\" or [" + " " + "] while the type is \"A\".");
                }
            }

            //校验字符串长度
            int min = Integer.parseInt(templateMap.get("minlength").toString());
            int max = Integer.parseInt(templateMap.get("maxlength").toString());
            if (value.indexOf(".") != -1 && (type.equals("9"))) {
                String num[] = value.split("\\.");
                if (num[0].length() > max) {
                    throw new InvalidDataException("rangeError!The value[" + num[0] + "]'s length is more than " + max + ".");
                }
                if (num[1].length() > min) {
                    throw new InvalidDataException("rangeError!The value[" + num[1] + "]'s length is more than " + min + ".");
                }
            } else {
                int length = xmlMap.get(id).toString().length();
                if (length < min) {
                    log.info(id + "Length should be greater than or equal to" + min + "，please check！");
                    throw new InvalidDataException("rangeError!The value[" + value + "]'s length is less than " + min + ".");

                }
                if (length > max) {
                    log.info(id + "Length should be less than or equal to" + max + "，please check！");
                    throw new InvalidDataException("rangeError!The value[" + value + "]'s length is more than " + max + ".");
                }
            }
        }
        return true;
    }

    //配置文件密码读取-输入密文，返回明文
    public static String passwordRead(String passwd) {
        return new DesReader().read(passwd);
    }
    //配置文件密文生成-输入明文，返回密文
    public static String passwordWrite(String passwd) {
        return new DesReader().write(passwd);
    }

}