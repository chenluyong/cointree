/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

DeriveTag
*/
package com.bepal.coins.keytree.infrastructure.tags;

public enum DeriveTag {
    tagDEFAULT(0),
    tagBITCOIN(0),
    tagED25519(1),
    tagSECP256R1(2);

    private final int val;

    DeriveTag(int val) {
        this.val = val;
    }
}
