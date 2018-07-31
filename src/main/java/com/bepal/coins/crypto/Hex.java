package com.bepal.coins.crypto;


/**
 * Created by 10254 on 2017-08-02.
 */
public class Hex {
    /**
     * 将16进制字符串转成字符串
     */
    public static String fromHexStringToString(String value) {
        try {
            return new String(fromHexString(value), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static byte[] fromHexString(String value) {
        value = value.toUpperCase();
        byte[] arr = new byte[value.length() / 2];
        char[] carr = value.toCharArray();
        String strTemp = "0123456789ABCDEF";
        for (int i = 0; i < carr.length; i += 2) {
            byte one = (byte) strTemp.indexOf(carr[i]);
            byte two = (byte) strTemp.indexOf(carr[i + 1]);
            arr[i / 2] = (byte) (one << 4 | two);
        }
        return arr;
    }


    /**
     * 将字符串转成16进制字符串
     */
    public static String toHexString(String value) {
        try {
            byte[] arr = value.getBytes("UTF-8");
            return toHexString(arr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String toHexString(byte[] value) {
        if (value == null) {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder();
        byte[] arr = value;
        for (byte item : arr) {
            String now = Integer.toHexString(item & 0xFF);
            if (now.length() == 1) {
                stringBuilder.append(0);
            }
            stringBuilder.append(now);
        }
        return stringBuilder.toString();
    }
}
