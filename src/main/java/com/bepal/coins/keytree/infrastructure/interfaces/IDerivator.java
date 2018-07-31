/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

IDerivator
*/
package com.bepal.coins.keytree.infrastructure.interfaces;

import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;

public interface IDerivator {
    /**
     * derive child eckey according to chain
     * */
    ECKey deriveChild(ECKey ecKey, Chain chain);

    /**
     * derive child public key according to chain, using public key
     * */
    ECKey deriveChildPub(ECKey ecKey, Chain chain);

    /**
     * derivate from seed
     * @param seedTag derive seed type
     * */
    ECKey deriveFromSeed(byte[] seed, SeedTag seedTag);

    /**
     * derivate from private key
     * */
    byte[] derivePubKey(byte[] priKey);
}
