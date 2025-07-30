package com.pingan.b2bic.Util;

import java.io.UnsupportedEncodingException;

/**
 * type支持：X ,9,R
 * X: 字符串类型，右补空格；
 * 9： 数字类型，左补0；
 * R:字符串类型，左补空格；
 * **/
public class FixedString{
    String key;
    int length;
    public String getKey() {
        return key;
    }
    public int getLength() {
        return length;
    }
    public char getType() {
        return type;
    }
    char type;// X ,9,R

    public FixedString(String key , int length, char type){
        this.key=key;
        this.length=length;
        this.type=type;
    }
    public String toString(){
        return this.key+"|"+this.length;
    }

    /**
     * 返回定长值
     * type支持以下类型
     * X: 字符串类型，右补空格；
     * 9： 数字类型，左补0；
     * R:字符串类型，左补空格；
     * @throws
     * */
    public static String getFixedValue(String value,String encoding, int length, char type)  {
        if(value==null) value="";
        StringBuffer src=new StringBuffer(value);
        StringBuffer pre=new StringBuffer();
        if(src.length()<length){
            int difflength=0;
            try {
                difflength = length- value.getBytes(encoding).length;
                //Trace.logInfo(Trace.COMPONENT_ACTION, "value["+value+"],encode["+encoding+"],length["+length+"],difflenght["+difflength+"]");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                //difflength = length- value.getBytes().length;
            }
            if(type=='9'){
                //数组型，左补0
                for(int i=0; i< difflength ;i++){
                    pre.append("0");
                }
                src=pre.append(src);
            }else if(type=='X'){
                //字符型，右补空格
                for(int i=0; i< difflength ;i++){
                    pre.append(" ");
                }
                src=src.append(pre);
            }else if(type=='R'){
                //R:字符串类型，左补空格；
                for(int i=0; i< difflength ;i++){
                    pre.append(" ");
                }
                src=pre.append(src);
            }
        }else if(src.length()>length){
            src=new StringBuffer(src.substring(0, length));
        }
        return src.toString();
    }

    public static byte[] toFixedLen(byte[] src, int len, byte padCharByte, String alignment) {

        int realLen = src.length;

        byte[] retBytes = new byte[len];
        for (int i = 0; i < len; i++) {
            retBytes[i] = padCharByte;
        }

        int b = 0;		//目标字节数组起始处
        int b1 = 0;		//源字节数组起始处
        //
        if ("right".equalsIgnoreCase(alignment)) {
            //右对齐
            if (realLen > len) {
                b1 = realLen - len;
                realLen = len;
            }
            b = len - realLen;
        } else if ("center".equalsIgnoreCase(alignment)) {
            if (realLen > len) {
                b1 = realLen / 2 - len / 2;
                realLen = len;
            }
            b = len / 2 - realLen / 2;
        } else {
            //左对齐
            if (realLen > len) {
                realLen = len;
            }
        }

        System.arraycopy(src, b1, retBytes, b, realLen);
        return retBytes;
    }

}

