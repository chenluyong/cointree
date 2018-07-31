/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

Bytomer
*/
package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.coinkey.BytomKey;
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

public class Bytomer implements ICoiner {

    private static final int BIP44INDEX= 153;

    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519);
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagHMAC512_ROOT);
        if (ecKey== null) return null;

        List<Chain> chains= new ArrayList<>();
        chains.add(new Chain(44, true, 2));
        chains.add(new Chain(BIP44INDEX, true, 2));
        chains.add(new Chain(0, true, 2));

        for (Chain chain: chains) {
            ecKey= derivator.deriveChild(ecKey, chain);
        }
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return new BytomKey(ecKey);
    }

    @Override
    public ICoinKey deriveSecChild(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0, false, 2);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new BytomKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0, false, 2);
        ecKey= derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new BytomKey(tmpKey));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519);

        Chain chain= new Chain(0, false, 2);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChildPub(ecKey, chain);
        }
        return new BytomKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519);

        Chain chain= new Chain(0, false, 2);
        ecKey= derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);

            coinKeys.add(new BytomKey(tmpKey));
        }

        return coinKeys;
    }
}
