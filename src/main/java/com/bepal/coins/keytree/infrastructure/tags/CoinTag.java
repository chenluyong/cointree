/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

CoinTag
*/
package com.bepal.coins.keytree.infrastructure.tags;

public enum CoinTag {
    tagBITCOIN(0),
    tagETHEREUM(1),
    tagBYTOM(2),
    tagEOS(3),
    tagGXCHAIN(4),
    tagSELFSELL(5),
    ;


    private final int val;
    CoinTag(int val) {
        this.val= val;
    }
}
