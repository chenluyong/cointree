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

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.derivator.BitcoinDerivator;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.models.ByteArrayData;

public class ECKey {
    protected byte[] priKey;
    protected byte[] pubKey;
    protected byte[] chainCode;
    protected IDerivator derivator;

    ECKey(){

    }

    public ECKey(ECKey ecKey) {
        this(ecKey.priKey,ecKey.pubKey,ecKey.chainCode,ecKey.derivator);
    }

    public ECKey(byte[] priKey, byte[] pubKey, byte[] chainCode, CoinTag coinTag) {
        this(priKey,pubKey,chainCode,
                DeriveCoordinator.findDerivator(CoinConfigFactory.getConfig(coinTag).getDeriveTag()));
    }

    public ECKey(byte[] priKey, byte[] pubKey, byte[] chainCode, IDerivator derivator) {
        setPriKey(priKey);
        setPubKey(pubKey);
        setChainCode(chainCode);
        setDerivator(derivator);
    }

    public ECKey(byte[] priKey, byte[] pubKey, byte[] chainCode) {
        this(priKey,pubKey,chainCode, new BitcoinDerivator());
    }


    public byte[] getPriKey() {
        return priKey;
    }


    public byte[] getPubKey() {
        if (null == pubKey) {
            pubKey = derivator.derivePubKey(priKey);
        }
        return pubKey;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    ///////////////////////////// 禁止外部二次设置类内变量 ///////////////////////////////////
    protected void setPubKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

    protected void setPriKey(byte[] priKey) {
        if (priKey!= null&& priKey[0]== 0&& priKey.length> 32) {
            priKey= ByteArrayData.copyOfRange(priKey, 1, 32);
        }
        this.priKey = priKey;
    }

    protected void setChainCode(byte[] chainCode) {
        if (chainCode!= null&& chainCode[0]== 0&& chainCode.length> 32) {
            chainCode= ByteArrayData.copyOfRange(chainCode, 1, 32);
        }

        this.chainCode = chainCode;
    }

    protected void setDerivator(IDerivator derivator) {
        this.derivator = derivator;
    }
}
