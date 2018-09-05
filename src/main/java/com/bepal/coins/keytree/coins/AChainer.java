/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: ${YAER}.08.07               |
|                                            |
╰============================================╯

AChainer
*/
package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.coinkey.AChainKey;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

import java.util.ArrayList;
import java.util.List;

public class AChainer extends ACoiner {

    private static final int BIP44INDEX= 666;

    public AChainer() {
        super(CoinConfigFactory.getConfig(CoinTag.tagAChain));
    }

    public AChainer(NetType netType) {
        super(CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagAChain : CoinTag.tagACHAINTEST
        ));
    }
}
