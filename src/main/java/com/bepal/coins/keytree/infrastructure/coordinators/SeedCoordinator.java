/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

SeedCoordinator
*/
package com.bepal.coins.keytree.infrastructure.coordinators;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;

public final class SeedCoordinator {

    private static SeedCoordinator instance;

    private SeedCoordinator() {}

    public static SeedCoordinator getInstance() {
        if (null == instance) {
            instance= new SeedCoordinator();
        }
        return instance;
    }

    public byte[] deriveMaster(byte[] seed, SeedTag seedTag) {
        switch (seedTag) {
            case tagHMAC512_ROOT: {
                return deriveHmac512_Root(seed);
            }
            default:
                return deriveBitcoin(seed);
        }
    }

    private byte[] deriveBitcoin(byte[] seed) {
        return SHAHash.Hmac512("Bitcoin seed".getBytes(), seed);
    }

    private byte[] deriveHmac512_Root(byte[] seed) {
        return SHAHash.Hmac512("Root".getBytes(), seed);
    }
}
