/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

SeedTag
*/
package com.bepal.coins.keytree.infrastructure.tags;

public enum SeedTag {
    tagDEFAULT(0),
    tagBITCOIN(0),
    tagHMAC512_ROOT(1)
    ;

    private final int val;
    SeedTag(int val) {
        this.val= val;
    }
}
