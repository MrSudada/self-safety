package com.pingan.b2bic.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;

public class B2BiClientUtil {
    public static String getLocalMac() throws SocketException,
            UnknownHostException {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("windows")) {
            StringBuffer sb = new StringBuffer();
            InetAddress ia = InetAddress.getLocalHost();
            byte[] mac = NetworkInterface.getByInetAddress(ia).getHardwareAddress();
            for (int i = 0; i < mac.length; i++) {
                if (i != 0) {
                    sb.append("-");
                }
                // 字节转换为整数
                int temp = mac[i] & 0xff;
                String str = Integer.toHexString(temp);
                if (str.length() == 1) {
                    sb.append("0" + str.toUpperCase());
                } else {
                    sb.append(str.toUpperCase());
                }
            }

            return sb.toString();

        } else {
            //linux/unix
            return getUnixMACAddress();
        }


    }

    /**
     * 获取Unix网卡的mac地址.
     *
     * @return mac地址
     */
    public static String getUnixMACAddress() {
        String mac = null;
        BufferedReader bufferedReader = null;
        Process process = null;
        try {
            /**
             *  Unix下的命令，一般取eth0作为本地主网卡 显示信息中包含有mac地址信息
             */
            process = Runtime.getRuntime().exec("ifconfig eth0");
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = null;
            int index = -1;
            while ((line = bufferedReader.readLine()) != null) {
                /**
                 *  寻找标示字符串[hwaddr]
                 */
                index = line.toLowerCase().indexOf("hwaddr");
                /**
                 * 找到了
                 */
                if (index != -1) {
                    /**
                     *   取出mac地址并去除2边空格
                     */
                    mac = line.substring(index + "hwaddr".length() + 1).trim();
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            bufferedReader = null;
            process = null;
        }

        return mac;
    }


    /**
     * 根据网卡获得IP地址，防止获取到127.0.0.1
     *
     * @return
     * @throws SocketException
     * @throws UnknownHostException
     */
    public static String getUnixIpAdd() throws SocketException, UnknownHostException {
        String ip = "";
        for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
            NetworkInterface intf = en.nextElement();
            String name = intf.getName();
            if (!name.contains("docker") && !name.contains("lo")) {
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    //获得IP
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        String ipaddress = inetAddress.getHostAddress().toString();
                        if (!ipaddress.contains("::") && !ipaddress.contains("0:0:") && !ipaddress.contains("fe80")) {

                            if (!"127.0.0.1".equals(ip)) {
                                ip = ipaddress;
                            }
                        }
                    }
                }
            }
        }
        return ip;
    }

    public static String getLocalIp() throws UnknownHostException, SocketException {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("windows")) {
            return InetAddress.getLocalHost().getHostAddress();
        } else {
            return getUnixIpAdd();
        }

    }

    /**
     * @param args
     * @throws UnknownHostException
     * @throws SocketException
     */
    public static void main(String[] args) throws SocketException, UnknownHostException {
        // TODO Auto-generated method stub
        System.out.println(getLocalMac());
        System.out.println(getLocalIp());
    }

}
