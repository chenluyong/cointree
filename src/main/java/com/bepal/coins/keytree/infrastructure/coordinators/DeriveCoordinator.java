/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

DeriveCoordinator
*/
package com.bepal.coins.keytree.infrastructure.coordinators;

import com.bepal.coins.keytree.infrastructure.derivator.BitcoinDerivator;
import com.bepal.coins.keytree.infrastructure.derivator.ED25519Derivator;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;

public final class DeriveCoordinator {

    private static DeriveCoordinator instance;

    private DeriveCoordinator() {}

    public static DeriveCoordinator getInstance() {
        if (null== instance) {
            instance= new DeriveCoordinator();
        }
        return instance;
    }

    public IDerivator findDerivator(DeriveTag deriveTag) {
        switch (deriveTag) {
            case tagED25519: {
                return new ED25519Derivator();
            }
            default: {
                return new BitcoinDerivator();
            }
        }
    }
}
