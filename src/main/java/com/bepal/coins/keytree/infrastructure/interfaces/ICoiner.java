/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

ICoiner
*/
package com.bepal.coins.keytree.infrastructure.interfaces;

import com.bepal.coins.keytree.model.ECKey;

import java.util.List;

public interface ICoiner extends ICoin{

    /**
     * according to bip44 derive key
     */
    ICoinKey deriveBip44(byte[] seed);

    /**
     * derive second layer child
     * */
    ICoinKey deriveSecChild(ECKey ecKey);

    /**
     * derive second layer child range
     * */
    List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end);

    /**
     * derive second layer child public key by public key
     * */
    ICoinKey deriveSecChildPub(ECKey ecKey);

    /**
     * derive second layer child public key range by public key
     * */
    List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end);

}
