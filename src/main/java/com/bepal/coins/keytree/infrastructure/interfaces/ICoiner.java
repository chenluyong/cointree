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
import com.bepal.coins.keytree.model.HDKey;

import java.util.List;

public interface ICoiner extends ICoin{

    /**
     * according to bip44 derive key
     */
    HDKey deriveBip44(byte[] seed);

    /**
     * derive second layer child
     * */
    HDKey deriveSecChild(HDKey hdKey);

    /**
     * derive second layer child range
     * */
    List<HDKey> deriveSecChildRange(HDKey hdKey, int start, int end);

    /**
     * derive second layer child public key by public key
     * */
    HDKey deriveSecChildPub(HDKey hdKey);

    /**
     * derive second layer child public key range by public key
     * */
    List<HDKey> deriveSecChildRangePub(HDKey hdKey, int start, int end);

}
