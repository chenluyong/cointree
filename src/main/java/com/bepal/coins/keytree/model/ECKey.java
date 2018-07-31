/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

ECKey
*/
package com.bepal.coins.keytree.model;

import com.bepal.coins.models.ByteArrayData;

public class ECKey {
    protected byte[] priKey;
    protected byte[] pubKey;
    protected byte[] chainCode;

    public byte[] getPriKey() {
        return priKey;
    }

    public void setPriKey(byte[] priKey) {
        if (priKey!= null&& priKey[0]== 0&& priKey.length> 32) {
            priKey= ByteArrayData.copyOfRange(priKey, 1, 32);
        }

        this.priKey = priKey;
    }

    public byte[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public void setChainCode(byte[] chainCode) {
        if (chainCode!= null&& chainCode[0]== 0&& chainCode.length> 32) {
            chainCode= ByteArrayData.copyOfRange(chainCode, 1, 32);
        }

        this.chainCode = chainCode;
    }
}
