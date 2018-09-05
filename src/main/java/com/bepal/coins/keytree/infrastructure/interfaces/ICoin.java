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

}
