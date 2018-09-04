package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;

public class CoinConfigFactory {
    // https://gitlab.eshanren.com/chenluyong/bepal/blob/master/doc/protocol/table.md
    static public CoinConfig getConfig(CoinTag coinTag) {
        switch (coinTag) {
            case tagBITCOIN:
                return new CoinConfig(DeriveTag.tagBITCOIN, CoinTag.tagBITCOIN, SeedTag.tagBITCOIN,
                        SignerTag.tagSECP256K1, 0, ICoin.NetType.MAIN);

            case tagBITCOINTEST:
                return new CoinConfig(DeriveTag.tagBITCOIN,CoinTag.tagBITCOINTEST,SeedTag.tagBITCOIN,
                        SignerTag.tagSECP256K1, 0, ICoin.NetType.TEST,0x043587CF,0x04358394);
        }

        // 默认比特币主网
        return new CoinConfig(DeriveTag.tagBITCOIN, CoinTag.tagBITCOIN, SeedTag.tagBITCOIN,
                SignerTag.tagSECP256K1, 0, ICoin.NetType.MAIN);
    }

}
