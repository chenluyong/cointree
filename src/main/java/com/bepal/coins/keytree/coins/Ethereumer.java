package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class Ethereumer extends ACoiner {
    public Ethereumer() {
        super(CoinConfigFactory.getConfig(CoinTag.tagETHEREUM));
    }

    public Ethereumer(NetType netType) {
        super(CoinConfigFactory.getConfig(
                ICoin.NetType.MAIN == netType ? CoinTag.tagETHEREUM :  CoinTag.tagETHEREUMTEST)
        );
    }
}
