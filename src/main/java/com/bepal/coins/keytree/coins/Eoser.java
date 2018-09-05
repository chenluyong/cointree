package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class Eoser extends ACoiner {

    public Eoser() {
        super(CoinConfigFactory.getConfig(CoinTag.tagEOS));
    }

    public Eoser(NetType netType) {
        super(CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagEOS :  CoinTag.tagEOSTEST)
        );
    }
}
