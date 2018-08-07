/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: ${YAER}.08.07               |
|                                            |
╰============================================╯

AChainKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

public class AChainKey implements ICoinKey {
    private ECKey ecKey;

    public AChainKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }

    @Override
    public ECKey base() {
        return this.ecKey;
    }

    @Override
    public String address() {
        return null;
    }

    @Override
    public String publicKey() {
        return "ACT"+ GrapheneSerializer.serializePubKey(this.ecKey.getPubKey());
    }

    @Override
    public String privateKey() {
        return GrapheneSerializer.wifPriKey(this.ecKey.getPriKey());
    }

    @Override
    public ECSign sign(byte[] hash) {
        return null;
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        return false;
    }
}
