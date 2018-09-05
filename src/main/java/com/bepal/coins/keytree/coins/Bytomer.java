package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.Chain;


public class Bytomer extends ACoiner {



    public Bytomer() {
        super(CoinConfigFactory.getConfig(CoinTag.tagBYTOM));
    }

    public Bytomer(CoinConfig config) {
        super(config);
    }
    public Bytomer(NetType netType) {
        super(CoinConfigFactory.getConfig(
            NetType.MAIN == netType ? CoinTag.tagBYTOM : (
                    NetType.TEST == netType ? CoinTag.tagBYTOMTEST : CoinTag.tagBYTOMSOLO
            )
        ));
    }


    @Override
    protected Chain getChain(int path, boolean hardened) {
        return new Chain(path, hardened,2);
    }


}
