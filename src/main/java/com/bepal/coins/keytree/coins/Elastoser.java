package com.bepal.coins.keytree.coins;


import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class Elastoser extends ACoiner {


    public Elastoser() {
        super(CoinConfigFactory.getConfig(CoinTag.tagELASTOS));
    }

    public Elastoser(NetType netType) {
        super(CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagELASTOS :  CoinTag.tagELASTOSTEST)
        );
    }

}
