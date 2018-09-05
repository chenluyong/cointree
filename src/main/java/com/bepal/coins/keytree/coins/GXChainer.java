package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class GXChainer extends ACoiner {
    public GXChainer() {
        super(CoinConfigFactory.getConfig(CoinTag.tagGXCHAIN));
    }

    public GXChainer(NetType netType) {
        super(CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagGXCHAIN :  CoinTag.tagGXCHAINTEST)
        );
    }
}
