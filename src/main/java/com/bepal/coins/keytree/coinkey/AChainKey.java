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

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

public class AChainKey extends ACoinKey {

    public AChainKey(ECKey ecKey) {
        super(ecKey,0,0);
    }
    public AChainKey(ECKey _ecKey, int _depth, int _path) {
        super(_ecKey,_depth,_path);
    }


    @Override
    public String address() {
        byte[] pubKey= this.ecKey.getPubKey();
        byte[] addr= SHAHash.sha512hash160(pubKey);
        byte[] checksum= SHAHash.RIPEMD160(addr);

        byte[] result= new byte[24];
        System.arraycopy(addr, 0, result, 0, addr.length);
        System.arraycopy(checksum, 0, result, addr.length, 4);
        return "ACT" + Base58.encode(result);
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
