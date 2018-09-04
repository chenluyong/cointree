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

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.keytree.coinkey.BitcoinKey;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.HDKey;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Bitcoiner extends ACoiner {

    private static final int BIP44INDEX= 0;

    public Bitcoiner() {
        super(new Config(DeriveTag.tagBITCOIN,CoinTag.tagBITCOIN,SeedTag.tagBITCOIN,
                SignerTag.tagSECP256K1, BIP44INDEX, NetType.MAIN));
    }

    public Bitcoiner(NetType netType) {
        super(new Config(DeriveTag.tagBITCOIN,CoinTag.tagBITCOIN,SeedTag.tagBITCOIN,
                SignerTag.tagSECP256K1, BIP44INDEX, netType));
    }

//
//    @Override
//    public List<HDKey> deriveSecChildRange(HDKey ecKey, int start, int end) {
//        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
//
//        Chain chain= new Chain(0);
//        ecKey= derivator.deriveChild(ecKey, chain);
//        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
//
//        List<HDKey> coinKeys= new ArrayList<>();
//        for (int i= start; i<= end; i++) {
//            chain.setPath(i);
//            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
//            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));
//
//            coinKeys.add(new HDKey(tmpKey, 1,start));
//        }
//
//        return coinKeys;
//    }
//
//    @Override
//    public HDKey deriveSecChildPub(ECKey ecKey) {
//        Chain chain= new Chain(0);
//        for (int i= 0; i< 2; i++) {
//            ecKey= derivator.deriveChildPub(ecKey, chain);
//        }
//        return new HDKey(ecKey, 1, 2);
//    }
//
//    @Override
//    public List<HDKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
//        Chain chain= new Chain(0);
//        ecKey= derivator.deriveChildPub(ecKey, chain);
//
//        List<HDKey> coinKeys= new ArrayList<>();
//        for (int i= start; i<= end; i++) {
//            chain.setPath(i);
//            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);
//
//            coinKeys.add(new HDKey(tmpKey, 1, start));
//        }
//
//        return coinKeys;
//    }
}
