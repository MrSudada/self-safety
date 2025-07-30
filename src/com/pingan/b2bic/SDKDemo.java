package com.pingan.b2bic;

import com.pingan.b2bic.sign.SignUtil;
import org.apache.log4j.xml.DOMConfigurator;

import java.util.Map;

public class SDKDemo {

    private static String   bankInTest="A0010101010020108000000000100000000001084001  12345012025052719001720250527190017            ip=192.168.1.1|mac=60-6D-3C-71-0D-EC|ZuID=saas001-guolitaoTest|PlatformID=p001|appId=123456|appKey=a00000000000000000000000000000<?xml version=\"1.0\" encoding=\"GBK\"?><Result><Account>11014564835008</Account><CcyCode>RMB</CcyCode></Result>001988MIIFzgYJKoZIhvcNAQcCoIIFvzCCBbsCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCBLcwggSzMIIDm6ADAgECAgwatMsLZBj5ouxGJMMwDQYJKoZIhvcNAQEFBQAwKzELMAkGA1UEBhMCQ04xDDAKBgNVBAoMA1NEQjEOMAwGA1UEAwwFU0RCQ0EwHhcNMTQwOTI1MDIxOTE0WhcNMTcwOTI0MDIxOTE0WjCBtzENMAsGA1UEBh4EAEMATjETMBEGA1UECh4KAFMARABCAEMAQTEPMA0GA1UECx4GAFMARABCMR8wHQYDVQQLHhYARQBuAHQAZQByAHAAcgBpAHMAZQBzMV8wXQYDVQQDHlYAUwBEAEIAQAA5ADEAOQAyADEAOAA1ADMANwBfADkALQA4ADAAMAAtADAAMQAxAEAAMgAwADAAMAAwADAAMAAwADAAOQBAADAAMgAxADAAOQAxADYAMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAq8ckw0ji0wc7NkPuZVxVSssjYePg+aWk3tmjoWUwC1MN7OlPnsbpV5fyxwG1XEZ/r5BBd5ZbaQ7tXQnfEN2YYP5mc4tI7gwkM3uIy2J7LDbK0dgPByOqmPZAvZ9c0rj6LSTvwRnBr9nb+7oBWcimSxDBHrRkPn3HHqWGK29jDlMCAwEAAaOCAcwwggHIMA8GA1UdEwEBAAQFMAMBAQAwDgYDVR0PAQEABAQDAgDwMBQGCWCGSAGG+EIBAQEBAAQEAwIAgDAiBgNVHSMBAQAEGDAWgBTsphMLoEHYw4J0qLt2QygfOlwUFzCBnwYIKwYBBQUHAQEBAQAEgY8wgYwwgYkGCCsGAQUFBzAChn1sZGFwOi8vMTAuMi4xMDEuMTU6NDg5L0NOPVNEQkNBLENOPVNEQkNBLE9VPWNBQ2VydGlmaWNhdGVzLG89c2RiY2EsYz1jbj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTCBpgYDVR0fAQEABIGbMIGYMIGVoIGSoIGPhoGMbGRhcDovLzEwLjIuMTAxLjE1OjQ4OS9DTj1TREJDQSxDTj1TREJDQSxvdT1DUkxEaXN0cmlidXRlUG9pbnRzLG89c2RiY2EsYz1jbj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Y2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwIAYDVR0OAQEABBYEFCXNaQ45BQjm0xwb1ljGOZd4scKAMA0GCSqGSIb3DQEBBQUAA4IBAQAJz2seS5pGAZLWPMAbSowMwnYiVfF3ZTa4WUvzsJo38ML30odBiCIa93sKZwVJ8ZG9Z/xnSymzHRJzj+SyYquBuqynpBjevaUTBPAKtyZM+d99eel0pBnGngF0P0MjdFXO45+yX/nEAtFDdZ7OlciTDnntr2swlJ55o5Nt6eDlYZVxjnoGGc5lmSsitqP1uTEfYnwboOQzWeFblnqegKJ7jiIg+ksFfQPW5vvjWiqd8nI1jYMOaYNeklzuV9yYDGbObwVs/cl62j3HuBNY/D4nInYz415mmN8Myr7y89zbfgShod68NjRhWohoJ1bF70IWuvI/rx+oTZqPTCfxMyTHMYHgMIHdAgEBMDswKzELMAkGA1UEBhMCQ04xDDAKBgNVBAoTA1NEQjEOMAwGA1UEAxMFU0RCQ0ECDBq0ywtkGPmi7EYkwzAJBgUrDgMCGgUAMA0GCSqGSIb3DQEBAQUABIGAlABS2nNGA/KuzOC6pq4IXwXhn3eycDPBbPEpH8qCm4ONRgvdQEs3vawpybL8+YDgfa0CUgiyO3XSRiAXZDRqs246U3++NNWbhT5esHo8/7nf03+mF1yJUQAAOsUdgunrGUy6tshIqq2f3jBMUoFb5tqxk/vdlGPZicB7watX6JQ=";
    public static void main(String[] args) throws Exception {

        //密码加密，适用配置文件生成
        String password = B2BICUtils.passwordWrite("12345678");
        System.out.println(password);
        String pass2 = B2BICUtils.passwordRead(password);
        System.out.println(pass2);

        //仅仅为了显示log4j日志，实际使用请勿使用
        DOMConfigurator.configureAndWatch("./configuration/log4j.xml");



        String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<Result>\n" +
                "<InstNo>监管机构代码</InstNo>\n" +
                "<QryAccNo>监管帐号</QryAccNo>\n" +
                "<BgnDate>查询起始日期</BgnDate>\n" +
                "<EndDate>查询截至日期</EndDate>\n" +
                "<GrpNum>总记录数</GrpNum>\n" +
                "<PackNum>1</PackNum>\n" +
                "<PackId>11111111</PackId>\n" +
                "</Result>";



        Map map1 = B2BICUtils.sendTobank(xmlFile, "01","02", "4001", "271000",
                "reqMsg=xxx|ZuID=xxxxA");
        System.out.println("map1 = " + map1);

        Map map3 = B2BICUtils.sendTobank(xmlFile, "01","02", "4001", "271000",
                "reqMsg=xxx|ZuID=xxxxA");
        System.out.println("map3 = " + map3);

        Map responseMap = B2BICUtils.sendTobank(xmlFile, "01","02", "4004",
                "271000","reqMsg=xxx|ZuID=xxxxA","cert/testrsa2022_04_01.pfx","12345678","RSA_SOFT");
        System.out.println("map = " + responseMap);



        Map map4 = B2BICUtils.sendTobank(xmlFile, "01","02", "4004", "271000",
                "reqMsg=xxx|ZuID=xxxxA");
        System.out.println("map4 = " + map4);


        Map map5 = B2BICUtils.sendTobank(xmlFile, "01","02", "4004", "271000",
                "reqMsg=xxx|ZuID=xxxxA","cert/sm2test20240923-18.pfx","12345678","SM2_SOFT");
        System.out.println("map5 = " + map5);

        Map map6 = B2BICUtils.sendTobank(xmlFile, "01","02", "4004", "271000",
                "reqMsg=xxx|ZuID=xxxxA");
        System.out.println("map4 = " + map6);

        //只签名
        String signByte=B2BICUtils.sign(xmlFile.getBytes("UTF-8"),"UTF-8","cert/testrsa2022_04_01.pfx","12345678","RSA_SOFT");
        System.out.println("signByte:"+signByte);

        String signByte2=B2BICUtils.sign(xmlFile.getBytes("UTF-8"),"UTF-8","cert/sm2test20240923-18.pfx","12345678","SM2_SOFT");
        System.out.println("signByte2:"+signByte2);

        //文件压缩和加密
        String srcFile= SDKDemo.class.getResource("/").getPath() + "../template/4001.xml",
                zipFile=SDKDemo.class.getResource("/").getPath() +"../template/4001.xml.zip",
                localFileName="4001.xml.enc",
                encFile=SDKDemo.class.getResource("/").getPath() +"../template/"+localFileName,
                localFilePath =  SDKDemo.class.getResource("/").getPath()+"../template/";
        //加压
        SignUtil.compress(srcFile, zipFile);
        // 加密
        String fpassword = SignUtil.encrypt(zipFile, encFile);
        System.out.println("fpassword = " + fpassword);
        //文件传输到sftp服务-upload

        B2BICUtils.sftpTransfer(B2BICUtils.TRAN_TYPE_UPLOAD,localFileName,localFilePath,localFileName);

        //文件下载
        String remoteFileName="4001.xml.enc",localFileName2="4001.xml.enc.down";
        B2BICUtils.sftpTransfer(B2BICUtils.TRAN_TYPE_DOWNLOAD,remoteFileName,localFilePath,localFileName2);

        //文件解密和解压
        String downZipFile="4001.xml.zip.2",desFile="4001.down.xml";
        SignUtil.decrypt(localFilePath+localFileName2, localFilePath+downZipFile, fpassword);
        // 解压
        SignUtil.uncompress(localFilePath+downZipFile, localFilePath+desFile);


        //下行通讯签名验证
        B2BICUtils.bankInSignVerify(bankInTest.getBytes(),"UTF-8");
    }
}
