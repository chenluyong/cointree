/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

GXChainer
*/
package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.coinkey.GXChainKey;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GXChainer extends ACoiner {

    private static final int BIP44INDEX= 2303;

    /**
     * coin type: main or test
     * */
    private int type= 0;


    public GXChainer() {
        super(DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT),BIP44INDEX, NetType.MAIN);
    }

    public GXChainer(NetType _netType) {
        super(DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT),BIP44INDEX, _netType);
    }

    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagDEFAULT);
        if (ecKey== null) return null;

        HDKey hdKey = this.deriveBip44(ecKey);
        if (hdKey== null) return null;

        return new GXChainKey(hdKey.getEcKey(), hdKey.getDepth(), hdKey.getPath());
    }

    @Override
    public ICoinKey deriveSecChild(ECKey ecKey) {
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new GXChainKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end) {
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        ecKey= derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain= new Chain(i);
            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new GXChainKey(tmpKey));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(ECKey ecKey) {
        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChildPub(ecKey, chain);
        }
        return new GXChainKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
        Chain chain= new Chain(0);
        ecKey= derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain= new Chain(i);
            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);

            coinKeys.add(new GXChainKey(tmpKey));
        }

        return coinKeys;
    }
}
