/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

Chain
*/
package com.bepal.coins.keytree.model;

import com.bepal.coins.utils.ByteUtil;

import java.text.MessageFormat;

public class Chain {
    private int path;


    private int pathType= 0;
    private boolean hardened;

    public Chain(int path) {
        this.path= path;
        this.hardened= false;
    }

    public Chain(int path, boolean hardened) {
        this.path= path;
        this.hardened= hardened;
    }

    public Chain(int path, boolean hardened, int pathType) {
        this.path= path;
        this.hardened= hardened;
        this.pathType= pathType;
    }

    public Chain(Chain chain) {
        this.path= chain.path;
        this.pathType= chain.pathType;
        this.hardened= chain.hardened;
    }

    public boolean isHardened() {
        return hardened;
    }


    ///////////////////////////// get / set /////////////////////////////////

    public int getPathType() {
        return pathType;
    }

    public void setPathType(int pathType) {
        this.pathType = pathType;
    }

    public void setPath(int path) {
        this.path= path;
    }

    public byte[] getPath() {
        if (pathType== 1) {

            /**
             * Nem路径
             * */
            return ByteUtil.intToBytes(this.path);
        } else if (pathType== 2) {

            /**
             * Btm路径
             * */
            return ByteUtil.longToBytes(path);
        } else {

            /**
             * SECP256k1家族的路径
             */
            long tmp= this.path;
            if (this.hardened) {
                tmp+= 0x80000000;
            }
            return ByteUtil.intToBytesLE(tmp);
        }
    }

    @Override
    public String toString() {
        return MessageFormat.format("{0} {1}", this.path, this.hardened ? "H" : "");
    }
}
