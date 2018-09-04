/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

Bitcoiner
*/
package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class Bitcoiner extends ACoiner {

    public Bitcoiner() {
        super(CoinConfigFactory.getConfig(CoinTag.tagBITCOIN));
    }

    public Bitcoiner(NetType netType) {
            super(CoinConfigFactory.getConfig(
                    NetType.MAIN == netType ? CoinTag.tagBITCOIN : CoinTag.tagBITCOINTEST
            ));
    }
    public Bitcoiner(CoinConfig coinConfig) {
        super(coinConfig);
    }
}
