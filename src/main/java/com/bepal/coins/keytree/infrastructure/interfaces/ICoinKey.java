/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

ICoinKey
*/
package com.bepal.coins.keytree.infrastructure.interfaces;

import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

public interface ICoinKey extends ICoin {

   /**
    * hd key
    * */
    byte[] toStandardXPrivate(int prefix);
    byte[] toStandardXPublic(int prefix);

    /**
     * base ECKey`
     * */
    ECKey base();

    /**
     * localize address
     * */
    String address();

    /**
     * localize public key
     * */
    String publicKey();

    /**
     * localize private key
     * */
    String privateKey();

    /**
     * sign hash
     * */
    ECSign sign(byte[] hash);

    /**
     * verify the sign result
     * */
    boolean verify(byte[] hash, ECSign ecSign);
}
