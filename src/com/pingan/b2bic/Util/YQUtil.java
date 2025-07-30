package com.pingan.b2bic.Util;

import com.jcraft.jsch.*;
import com.pingan.b2bic.Config.FtpConfig;
import com.pingan.b2bic.Config.HttpServerConfig;
import com.pingan.b2bic.Config.HttpsServerConfig;
import com.pingan.b2bic.Exception.ConnException;
import com.pingan.b2bic.Http.HttpReqVo;
import com.pingan.b2bic.Http.HttpRspVo;
import com.pingan.b2bic.Http.RequestStream;
import com.pingan.b2bic.sign.Config;

import org.apache.commons.httpclient.ConnectMethod;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.HttpHost;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.ProxyHost;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.QName;

import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.*;

/**
 * 银企直连实用函数
 *
 * @author ZHANGXUELING871
 * @version 0.1
 * @since 2014-01-03
 */
public class YQUtil {
    private static final String version="SDK.b2bi.20250410";



    private static final Log log = LogFactory.getLog(YQUtil.class);

    private static final String fmtTime = "yyyyMMddHHmmss";

    public static final String HEAD_CONTENT_TYPE = "Content-Type";
    private static String DEFAULT_CONTTENT_TYPE = "text/html; charset=UTF-8";

    private static Map<String, ProtocolSocketFactory> socketFactoryMap = new HashMap<String, ProtocolSocketFactory>();

    private static Config config;
    private static HttpServerConfig serverConfig;
    private static FtpConfig bankftpCfg;

    static {
        config = Config.getInstance();
        serverConfig = (HttpServerConfig) config.getBankOutCfg();
        bankftpCfg = config.getBankftpCfg();
    }

    /**
     * @author          Anzhi
     * @param yqdm      20位银企代码
     * @param bsnCode   交易代码
     * @param xmlBody   xml主体报文
     * @return          报文头
     * @throws UnsupportedEncodingException
     * @since           2018/4/27
     */
    public static String asemblyPackets(String systemId,String encoding,
                                        String encode, String yqdm,
                                        String bsnCode,String reqMsg,
                                        String xmlBody) throws UnsupportedEncodingException {

        Date now = Calendar.getInstance().getTime();
        StringBuilder buf = new StringBuilder();
        buf.append("A001");
        buf.append(systemId);
        buf.append(encoding);//编码
        buf.append("01");//通讯协议为TCP/IP
        buf.append(yqdm);//银企代码
        buf.append(String.format("%010d", xmlBody.getBytes(encode).length));
        buf.append(String.format("%-6s", bsnCode));//交易码-左对齐
        buf.append("12345");//操作员代码-用户可自定义
        buf.append("01");//服务类型 01请求

        String fmtNow = new SimpleDateFormat(fmtTime).format(now);
        buf.append(fmtNow); //请求日期时间

        String requestLogNo = "YQTEST" + fmtNow;
        buf.append(requestLogNo);//请求方系统流水号

        buf.append(String.format("%6s", "")); //返回码
        try {
            reqMsg = reqMsg +"|ip="+B2BiClientUtil.getLocalIp()+"|mac="+B2BiClientUtil.getLocalMac()+"|v="+version;
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        buf.append(String.format("%100s", reqMsg));

        buf.append(0); //后续包标志
        buf.append(String.format("%03d", 0));//请求次数
        buf.append("0");//签名标识 0不签
        buf.append("1");//签名数据包格式
        buf.append(String.format("%12s", "")); //签名算法
        buf.append(String.format("%010d", 0)); //签名数据长度
        buf.append(0);//附件数目
        buf.append(xmlBody);//报文体

        return buf.toString();
    }



    /**
     * @author       Anzhi
     * @param map    Map
     * @return       Document
     * @throws Exception
     * @since:       2018/4/27
     */
    public static Document map2xml(Map<String, Object> map,String encode) throws Exception {

        Iterator<Map.Entry<String, Object>> entries = map.entrySet().iterator();
        Document doc = DocumentHelper.createDocument();
        doc.setXMLEncoding(encode);
        Element root = DocumentHelper.createElement(new QName("Result"));
        doc.add(root);
        while(entries.hasNext()){ //获取第一个键创建根节点
            Map.Entry<String, Object> entry = entries.next();
            //value类型为List，存在二级菜单
            if(entry.getValue() instanceof java.util.List){
                List<Map> list = (List) entry.getValue();
                for (Map nodeMap: list) {
                    Element node = DocumentHelper.createElement(new QName(entry.getKey()));
                    map2xml(nodeMap, node);
                    root.add(node);
                }
            }
            //value类型为String
            if(entry.getValue() instanceof java.lang.String){
                Element node = DocumentHelper.createElement(new QName(entry.getKey()));
                node.addText(entry.getValue().toString());
                root.add(node);
            }
        }
        return doc;
    }


    /**
     * 创建目录 进入最终目录
     *
     * @param createpath
     * @return
     */
    public static void createDir(String createpath, ChannelSftp sftp) throws SftpException {
        if (isDirExist(createpath, sftp)) {
            sftp.cd(createpath);

        }
        String pathArry[] = createpath.split("/");
        StringBuffer filePath = new StringBuffer("/");
        for (String path : pathArry) {
            if (path.equals("")) {
                continue;
            }
            filePath.append(path + "/");
            if (isDirExist(filePath.toString(), sftp)) {
                sftp.cd(filePath.toString());
            } else {
                // 建立目录
                sftp.mkdir(filePath.toString());
                // 进入并设置为当前目录
                sftp.cd(filePath.toString());
            }
        }
        sftp.cd(createpath);
    }

    /**
     * 判断目录是否存在
     * @param directory
     * @return
     */
    public static boolean isDirExist(String directory, ChannelSftp sftp)
    {
        boolean isDirExistFlag = false;
        try
        {
            SftpATTRS sftpATTRS = sftp.lstat(directory);
            isDirExistFlag = true;
            return sftpATTRS.isDir();
        }
        catch (Exception e)
        {
            if (e.getMessage().toLowerCase().equals("no such file"))
            {
                isDirExistFlag = false;
            }
        }
        return isDirExistFlag;
    }
    /**
     * @author         Anzhi
     * @param map      Map
     * @param body     Body
     * @return         Element
     * @exception
     * @since          2018/4/27
     */
    private static Element map2xml(Map<String, Object> map, Element body) {

        Iterator<Map.Entry<String, Object>> entries = map.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<String, Object> entry = entries.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if(key.startsWith("@")){    //属性
                body.addAttribute(key.substring(1, key.length()), value.toString());
            } else if(key.equals("#text")){ //有属性时的文本
                body.setText(value.toString());
            } else {
                if(value instanceof java.util.List ){
                    List list = (List)value;
                    Object obj;
                    for(int i=0; i<list.size(); i++){
                        obj = list.get(i);
                        //list里是map或String，不会存在list里直接是list的，
                        if(obj instanceof java.util.Map){
                            Element subElement = body.addElement(key);
                            map2xml((Map)list.get(i), subElement);
                        } else {
                            body.addElement(key).setText((String)list.get(i));
                        }
                    }
                } else if(value instanceof java.util.Map ){
                    Element subElement = body.addElement(key);
                    map2xml((Map)value, subElement);
                } else {
                    body.addElement(key).setText(value.toString());
                }
            }
        }
        return body;
    }

    /**
     * @author         Anzhi
     * @param xmlstr   待转换xml内容
     * @return         Map
     * @throws Exception
     * @since          2018/4/27
     */
    public static Map xml2map(String xmlstr) throws Exception {

        Map map = new HashMap();
        Map map2;
        Document document = null;
        document = DocumentHelper.parseText(xmlstr);
        List<Element> elementList= document.getRootElement().elements();

        for (Element e : elementList) {
            List list;
            //存在二级字段
            if(e.elements().size()!=0){
                map2 = xml2map(e.asXML());
                //标签出现不只一次，一定有二级字段
                if(map.containsKey(e.getName())){
                    list = (List) map.get(e.getName());
                }
                else {
                    list = new ArrayList();
                }
                list.add(map2);
                map.put(e.getName(),list);
            }
            else {
                map.put(e.getName(),e.getTextTrim());
            }
        }
        return map;
    }

    /**
     * 将字符串格式的报文头转换为Map
     *
     * @author        Anzhi
     * @param head    报文头
     * @return        Map报文头
     * @throws UnsupportedEncodingException
     * @since         2018/4/27
     */
    public static Map head2Map(byte[] head,String charset) throws UnsupportedEncodingException {

        Map<String,String> headMap = new HashMap();
        headMap.put("systemId", new String(head, 4, 2, charset));
        headMap.put("encoding", new String(head, 6, 2, charset));
        headMap.put("protocol", new String(head, 8, 2, charset));
        headMap.put("corpCode", new String(head, 10, 20, charset));
        headMap.put("dataBodyLen", new String(head, 30, 10, charset));
        headMap.put("tradeCode", new String(head, 40, 6, charset));
        headMap.put("operator", new String(head, 46, 5, charset));
        headMap.put("mode", new String(head, 51, 2, charset));
        headMap.put("tradeDate", new String(head, 53, 8, charset));
        headMap.put("tradeTime", new String(head, 61, 6, charset));
        headMap.put("reqSn", new String(head, 67, 10, charset));
        headMap.put("errCode", new String(head, 87, 6, charset));
        headMap.put("errMsg", new String(head, 93, 100, charset));
        headMap.put("toContinue", new String(head, 193, 2, charset));
        headMap.put("packetNo", new String(head, 194, 3, charset));
        headMap.put("signTag", new String(head, 197, 1, charset));
        headMap.put("signFormat", new String(head, 198, 1, charset));
        headMap.put("signAlgorithm", new String(head, 199, 12, charset));
        headMap.put("signDataLen", new String(head, 211, 10, charset));
        headMap.put("attachNum", new String(head, 221, 1, charset));
        for (Map.Entry<String, String> entry : headMap.entrySet()) {
            log.debug("Parsing fields" + entry.getKey() + " value: " + entry.getValue());
        }
        return headMap;
    }

    public static HttpRspVo send(byte[] src, String encode, RequestStream request)
            throws Exception {
        HttpConnection connection = (HttpConnection) request.getDataSource();
        HttpReqVo reqvo = new HttpReqVo();
        reqvo.setUrl(serverConfig.getUrl());
        reqvo.setBody(src);
        Map header = new HashMap();
        header.put("Content-Type","text/xml; charset="+encode);
        reqvo.setHeader(header);
        return postSend(connection, encode, reqvo);

    }

    public static HttpRspVo postSend(HttpConnection connection, String encode, HttpReqVo reqVo)
            throws IOException {
        if (log.isInfoEnabled()) {
            log.info("POST,URL=[" + reqVo.getUrl() + "],data["
                    + reqVo.getBody().length + "]:\n"
                    + new String(reqVo.getBody(),encode));
        }
        HttpMethod httpMethod = new PostMethod();
        httpMethod.setPath(reqVo.getUrl());
        ByteArrayRequestEntity entity = new ByteArrayRequestEntity(reqVo
                .getBody());
        ((PostMethod) httpMethod).setRequestEntity(entity);
        return doSend(connection, encode, httpMethod, reqVo.getHeader());
    }

    static HttpRspVo doSend(HttpConnection connection, String encode, HttpMethod httpMethod,
                            Map<String, String> header) throws IOException {
        if (!header.containsKey(HEAD_CONTENT_TYPE)) {
            httpMethod.setRequestHeader(HEAD_CONTENT_TYPE,
                    DEFAULT_CONTTENT_TYPE);
        }
        for (Iterator<Map.Entry<String, String>> iter = header.entrySet()
                .iterator(); iter.hasNext();) {
            Map.Entry<String, String> entry = iter.next();
            httpMethod.addRequestHeader(entry.getKey(), entry.getValue());
        }
        HttpRspVo vo = new HttpRspVo();
        int status = httpMethod.execute(new HttpState(), connection);
        vo.setStatus(status);
        if (log.isInfoEnabled()) {
            log.info("Return code:" + status);
        }
        Map<String, String> head = new HashMap<String, String>();
        Header[] headers = httpMethod.getResponseHeaders();
        for (int i = 0; i < headers.length; i++) {
            head.put(headers[i].getName(), headers[i].getValue());
            if (log.isDebugEnabled()) {
                log.debug("Header of Response:" + headers[i].getName() + " = "
                        + headers[i].getValue());
            }
        }
        vo.setHeader(head);
        byte[] repbody = httpMethod.getResponseBody();
        vo.setBody(repbody);
        if (log.isInfoEnabled()) {
            log
                    .info("Response message [" + repbody.length + "]:\n"
                            + new String(repbody,encode));
        }
        return vo;
    }

    public static RequestStream createReqestStream() throws ConnException {
        RequestStream rs = new RequestStream();
        HttpConnection connection = null;
        try {
            connection = genConnect(serverConfig);
        } catch(Exception e) {
            throw new ConnException(e);
        }
        rs.setDataSource(connection);
        return rs;
    }

    public static HttpConnection genConnect(HttpServerConfig config)
            throws IOException {
        InetSocketAddress address = config.getAddress()[0];
        log.info("Remote host : " + address);
        if (log.isDebugEnabled()) {
            log.debug( "Timeout (MS): " + config.getTimeout());
        }
        HttpConnection connection = null;


        //设置https代理
        if( config.getProxyHost() != null && config.getProxyHost().length()>1
                && config.getProxyPort()!=null && config.getProxyPort().length()>1
                && config instanceof HttpsServerConfig){
            log.info(" protocol: https, proxy server:"+config.getProxyHost()+":"+config.getProxyPort());
            ProtocolSocketFactory factory = rtrvSocketFactory((HttpsServerConfig) config);
            Protocol myhttps = new Protocol("https", factory, 443);

            HttpHost httpHost = new HttpHost(address.getHostName(), address
                    .getPort(),myhttps);
            HostConfiguration hostCfg = new HostConfiguration();
            hostCfg.setHost(httpHost);
            hostCfg.setProxyHost(new ProxyHost(config.getProxyHost(), Integer.parseInt(config.getProxyPort())));
            connection = new HttpConnection(hostCfg);
            HttpConnectionParams params = new HttpConnectionParams();
            DefaultHttpMethodRetryHandler handler = new DefaultHttpMethodRetryHandler(
                    0, false);
            params.setParameter(HttpMethodParams.RETRY_HANDLER, handler);
            if (config.getTimeout() > 0) {
                params.setSoTimeout(config.getTimeout());
                params.setConnectionTimeout(config.getTimeout());
            }
            connection.setParams(params);
            int retryNum = config.getConnectRetryNum();
            int failed = 0;
            while(true) {
                try {
                    connection.open();
                    ConnectMethod connectMethod = new ConnectMethod(hostCfg);
                    connectMethod.execute(new HttpState(), connection);
                    int code = connectMethod.getStatusCode();
                    if ((code >= 200) && (code < 300)) { // 代理验证通过
                        connection.tunnelCreated();
                    } else {
                        throw new IOException(
                                "Proxy Authenticate failure! Return code = [" + code
                                        + "]");
                    }
                    break;
                } catch(IOException e) {
                    if (retryNum-- > 0) {
                        log.warn("Failed to create connection，is " + (++failed) + "times trying...");
                        if (config.getConnectRetryInterval() > 0) {
                            try {
                                Thread.sleep(config.getConnectRetryInterval());
                            } catch(InterruptedException ex) {
                            }
                        }
                    } else {
                        throw e;
                    }
                }
            }

        }else{
            //非代理模式
            if (config instanceof HttpsServerConfig) {
                log.debug("protocol: https");
                ProtocolSocketFactory factory = rtrvSocketFactory((HttpsServerConfig) config);
                Protocol myhttps = new Protocol("https", factory, 443);
                connection = new HttpConnection(address.getHostName(), address
                        .getPort(), myhttps);

            } else {

                connection = new HttpConnection(address.getHostName(), address
                        .getPort());

                if( config.getProxyHost() != null && config.getProxyHost().length()>1
                        && config.getProxyPort()!=null && config.getProxyPort().length()>1
                        ){
                    //http协议使用代理
                    log.info("protocol: http, proxy server:"+config.getProxyHost()+":"+config.getProxyPort());
                    connection.setProxyHost(config.getProxyHost());
                    connection.setProxyPort(Integer.parseInt(config.getProxyPort()));
                }
            }



            HttpConnectionParams params = new HttpConnectionParams();
            DefaultHttpMethodRetryHandler handler = new DefaultHttpMethodRetryHandler(
                    0, false);
            params.setParameter(HttpMethodParams.RETRY_HANDLER, handler);
            if (config.getTimeout() > 0) {
                params.setSoTimeout(config.getTimeout());
                params.setConnectionTimeout(config.getTimeout());
            }
            connection.setParams(params);
            int retryNum = config.getConnectRetryNum();
            int failed = 0;
            while(true) {
                try {
                    connection.open();
                    break;
                } catch(IOException e) {
                    if (retryNum-- > 0) {
                        log.warn("Failed to create connection，is Reconnection of" + (++failed) + " times...");
                        if (config.getConnectRetryInterval() > 0) {
                            try {
                                Thread.sleep(config.getConnectRetryInterval());
                            } catch(InterruptedException ex) {
                            }
                        }
                    } else {
                        throw e;
                    }
                }
            }
        }

        return connection;
    }

    static ProtocolSocketFactory rtrvSocketFactory(HttpsServerConfig config)
            throws MalformedURLException {
        synchronized (socketFactoryMap) {
            ProtocolSocketFactory factory = socketFactoryMap
                    .get(config.getId());
            if (factory != null) {
                return factory;
            }
            factory = new AuthSSLProtocolSocketFactory(new URL("file:"
                    + config.getStorePath()), config.getStorePwd(), new URL(
                    "file:" + config.getTrustPath()), config.getTrustPwd());
            ((AuthSSLProtocolSocketFactory) factory).setKeyStoreType(config
                    .getStoreType());
            ((AuthSSLProtocolSocketFactory) factory)
                    .setTrustKeyStoreType(config.getTrustType());
            ((AuthSSLProtocolSocketFactory) factory).setAuthSrv(config.isAuthSrv());
            socketFactoryMap.put(config.getId(), factory);
            return factory;
        }
    }

    /**
     * 获取一个字符串以一个特定分割符划分的所有分节
     *
     * @param sSource
     *            要分割的字符串
     * @param sDelim
     *            分割符
     * @return 划分后的所有分节
     * @since StringTool 1.0
     */
    public static String[] getTokens(String sSource, String sDelim) {

        StringTokenizer tokenizer = new StringTokenizer(sSource, sDelim);
        int iCount = tokenizer.countTokens();
        String[] sTokens = new String[iCount];
        for (int i = 0; i < iCount; i++) {
            sTokens[i] = tokenizer.nextToken();
        }
        return (sTokens);
    }

    /**
     * 将数组转为字符串输出，数组元素使用分隔符分隔
     *
     * @param objs
     *            数组
     * @param separator
     *            分隔符
     * @return
     */
    public static String showArray(Object[] objs, String separator) {
        if (objs.length == 0) {
            return "";
        }
        StringBuffer ret = new StringBuffer(objs[0].toString());
        for (int i = 1; i < objs.length; i++) {
            ret.append(separator).append(objs[i].toString());
        }
        return ret.toString();
    }

    public static String getString(Object o) {
        return getString(o, "gbk");
    }

    public static String getString(Object o, String encoding) {
        if (o == null)
            return null;
        if (o instanceof byte[]) {
            String s = null;
            try {
                s = new String((byte[]) o, encoding);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                return null;
            }
            return s;
        } else if (o instanceof String) {
            return (String) o;
        } else
            return o.toString();
    }
    public static String fillString(String src , int length, String encoding) {
        if(src.length()>length){
            return src.substring(0,length);
        }
        else
            return FixedString.getFixedValue(src,encoding,length,'X');
    }

    /**
     * 用特定字符填充字符串
     *
     * @param sSrc
     *            要填充的字符串
     * @param ch
     *            用于填充的特定字符
     * @param nLen
     *            要填充到的长度
     * @param bLeft
     *            要填充的方向：true:左边；false:右边
     * @return 填充好的字符串
     */
    public static String fill(String sSrc, char ch, int nLen, boolean bLeft) {
        byte[] bTmp = trimnull(sSrc.getBytes());
        sSrc = new String(bTmp);
        if (sSrc == null || sSrc.equals("")) {
            StringBuffer sbRet = new StringBuffer();
            for (int i = 0; i < nLen; i++)
                sbRet.append(ch);

            return sbRet.toString();
        }
        byte[] bySrc = sSrc.getBytes();
        int nSrcLen = bySrc.length;
        if (nSrcLen >= nLen) {
            return sSrc;
        }
        byte[] byRet = new byte[nLen];
        if (bLeft) {
            for (int i = 0, n = nLen - nSrcLen; i < n; i++)
                byRet[i] = (byte) ch;
            for (int i = nLen - nSrcLen, n = nLen; i < n; i++)
                byRet[i] = bySrc[i - nLen + nSrcLen];
        } else {
            for (int i = 0, n = nSrcLen; i < n; i++)
                byRet[i] = bySrc[i];
            for (int i = nSrcLen, n = nLen; i < n; i++)
                byRet[i] = (byte) ch;
        }
        return new String(byRet);
    }

    /**
     * 去掉字符串两头的空值
     *
     * @param byRet
     *            要去除的字符串
     * @return 去除好的字符串
     */

    public static byte[] trimnull(byte[] byRet) {
        int startPos = 0;
        int endPos = byRet.length - 1;
        for (int i = 0; i < byRet.length; i++) {
            if (byRet[i] != 0) {
                startPos = i;
                break;
            }
            if (i == (byRet.length - 1) && byRet[i] == 0) {
                return null;
            }
        }
        for (int i = byRet.length - 1; i >= 0; i--) {
            if (byRet[i] != 0) {
                endPos = i;
                break;
            }
        }
        byte[] byTmp = new byte[endPos - startPos + 1];
        System.arraycopy(byRet, startPos, byTmp, 0, endPos - startPos + 1);
        return byTmp;
    }



}
