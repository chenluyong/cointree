package com.bepal.coins.keytree.infrastructure.interfaces;

import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;

public interface ICoin {

    /**
     * net type: main or test
     * */
    enum NetType {
        MAIN(0),
        TEST(1),
        SOLO(2);

        private final int val;
        NetType(int val) {
            this.val= val;
        }
    }

    CoinConfig config = null;

    class Config {
        public DeriveTag deriveTag;
        public CoinTag coinTag;
        public SeedTag seedTag;
        public SignerTag signerTag;
        // bip44 coin index
        // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        public long bip44;
        public NetType netType;
        public int pubPrefix;
        public int prvPrefix;

        public Config(DeriveTag deriveTag, CoinTag coinTag, SeedTag seedTag,
                      SignerTag signerTag, long bip44, NetType netType) {
            this.deriveTag = deriveTag;
            this.coinTag = coinTag;
            this.seedTag = seedTag;
            this.signerTag = signerTag;
            this.bip44 = bip44;
            this.netType = netType;
            this.pubPrefix = 0x0488B21E; // xpub
            this.prvPrefix = 0x0488ADE4; // xprv
        }
    }
}
