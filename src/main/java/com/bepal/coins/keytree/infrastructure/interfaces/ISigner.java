/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

ISigner
*/
package com.bepal.coins.keytree.infrastructure.interfaces;

import com.bepal.coins.keytree.model.ECSign;

public interface ISigner {

    /**
     * Sign data
     *
     * @param priKey for check if sign true
     * */
    ECSign sign(byte[] priKey, byte[] pubKey, byte[] hash);

    boolean verify(byte[] pubKey, byte[] hash, ECSign ecSign);
}
