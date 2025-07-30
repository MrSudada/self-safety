package com.pingan.b2bic.Util;

import java.io.UnsupportedEncodingException;

/**
 * type֧�֣�X ,9,R
 * X: �ַ������ͣ��Ҳ��ո�
 * 9�� �������ͣ���0��
 * R:�ַ������ͣ��󲹿ո�
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
     * ���ض���ֵ
     * type֧����������
     * X: �ַ������ͣ��Ҳ��ո�
     * 9�� �������ͣ���0��
     * R:�ַ������ͣ��󲹿ո�
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
                //�����ͣ���0
                for(int i=0; i< difflength ;i++){
                    pre.append("0");
                }
                src=pre.append(src);
            }else if(type=='X'){
                //�ַ��ͣ��Ҳ��ո�
                for(int i=0; i< difflength ;i++){
                    pre.append(" ");
                }
                src=src.append(pre);
            }else if(type=='R'){
                //R:�ַ������ͣ��󲹿ո�
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

        int b = 0;		//Ŀ���ֽ�������ʼ��
        int b1 = 0;		//Դ�ֽ�������ʼ��
        //
        if ("right".equalsIgnoreCase(alignment)) {
            //�Ҷ���
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
            //�����
            if (realLen > len) {
                realLen = len;
            }
        }

        System.arraycopy(src, b1, retBytes, b, realLen);
        return retBytes;
    }

}

