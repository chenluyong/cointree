/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

SinerTag
*/
package com.bepal.coins.keytree.infrastructure.tags;

public enum SignerTag {
    tagSECP256K1(0),
    tagSECP256K1NONCE(1),
    tagED25519(2)
    ;

    private final int val;
    SignerTag(int val) {
        this.val= val;
    }
}
