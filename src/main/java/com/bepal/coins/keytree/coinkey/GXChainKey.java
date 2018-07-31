/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

GXChainKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

public class GXChainKey implements ICoinKey {
    private ECKey ecKey;
    private int VERSION= 0;

    public GXChainKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }


    @Override
    public ECKey base() {
        return ecKey;
    }

    @Override
    public String address() {
//        byte[] pubKey= this.ecKey.getPubKey();
//        byte[] addr= SHAHash.sha512hash160(pubKey);
//        byte[] checksum= SHAHash.RIPEMD160(addr);
//
//        byte[] result= new byte[24];
//        System.arraycopy(addr, 0, result, 0, addr.length);
//        System.arraycopy(checksum, 0, result, addr.length, 4);
//        return "GXC" + Base58.encode(result);
        return publicKey();
    }

    @Override
    public String publicKey() {
        byte[] pubKey= this.ecKey.getPubKey();
        byte[] result= new byte[4+ pubKey.length];
        byte[] checksum= SHAHash.RIPEMD160(pubKey);
        System.arraycopy(pubKey, 0, result, 0, pubKey.length);
        System.arraycopy(checksum, 0, result, pubKey.length, 4);
        return "GXC" + Base58.encode(result);
    }

    @Override
    public String privateKey() {
        byte[] priKey= this.ecKey.getPriKey();
        byte[] toDigest= new byte[priKey.length+ 1];

        toDigest[0]= (byte)0x80;
        System.arraycopy(priKey, 0, toDigest, 1, priKey.length);
        byte[] digest= SHAHash.hash2256Twice(toDigest);

        byte[] result= new byte[priKey.length+ 5];
        System.arraycopy(toDigest, 0, result, 0, toDigest.length);
        System.arraycopy(digest, 0, result, toDigest.length, 4);
        return Base58.encode(result);
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
