package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class SelfSeller extends ACoiner {
    public SelfSeller() {
        super(CoinConfigFactory.getConfig(CoinTag.tagSELFSELL));
    }

    public SelfSeller(NetType netType) {
        super(CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagSELFSELL : CoinTag.tagSELFSELLTEST)
        );
    }
}
