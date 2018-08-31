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

import com.bepal.coins.keytree.coinkey.BitcoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;

import java.util.ArrayList;
import java.util.List;

public class Bitcoiner implements ICoiner {

    private static final int BIP44INDEX= 0;

    /**
     * net type: main or test
     * */
    private BitcoinKey.NetType type= BitcoinKey.NetType.MAIN;

    public Bitcoiner() { }

    public Bitcoiner(BitcoinKey.NetType netType) {
        this.type= netType;
    }

    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagBITCOIN);
        if (ecKey== null) return null;

        int secLayer= BIP44INDEX, thdLayer= 0;
        if (this.type!= BitcoinKey.NetType.MAIN) {
            secLayer= 1;
            thdLayer= BIP44INDEX;
        }

        List<Chain> chains= new ArrayList<>();
        chains.add(new Chain(44, true));
        chains.add(new Chain(secLayer, true));
        chains.add(new Chain(thdLayer, true));

        for (Chain chain: chains) {
            ecKey= derivator.deriveChild(ecKey, chain);
        }
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return new BitcoinKey(ecKey, this.type);
    }

    @Override
    public ICoinKey deriveSecChild(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new BitcoinKey(ecKey, this.type);
    }

    @Override
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        ecKey= derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new BitcoinKey(tmpKey, this.type));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);

        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChildPub(ecKey, chain);
        }
        return new BitcoinKey(ecKey, this.type);
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);

        Chain chain= new Chain(0);
        ecKey= derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);

            coinKeys.add(new BitcoinKey(tmpKey, this.type));
        }

        return coinKeys;
    }
}
