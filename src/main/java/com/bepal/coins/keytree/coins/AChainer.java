/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: ${YAER}.08.07               |
|                                            |
╰============================================╯

AChainer
*/
package com.bepal.coins.keytree.coins;

import com.bepal.coins.keytree.coinkey.AChainKey;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AChainer implements ICoiner {

    private static final int BIP44INDEX= 666;

    /**
     * coin type: main or test
     * */
    private NetType type = NetType.MAIN;

    public AChainer() { }

    public AChainer(NetType type) {
        this.type= type;
    }

    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT);
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagDEFAULT);
        if (ecKey== null) return null;

        int secLayer= BIP44INDEX, thdLayer= 0;
        if (this.type != NetType.MAIN) {
            secLayer= 1;
            thdLayer= BIP44INDEX;
        }

        List<Chain> chains= new ArrayList<>();
        chains.add(new Chain(44, true));
        chains.add(new Chain(secLayer, true));
        chains.add(new Chain(thdLayer, true));
        System.out.println(thdLayer);
        int depth = 0;
        int path = 0;
        for (Chain chain: chains) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ++depth;
            path = ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(),0,4)).getInt();
        }
        if (ecKey== null) return null;

        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return new AChainKey(ecKey, depth, path);
    }

    @Override
    public ICoinKey deriveSecChild(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new AChainKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT);
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0);
        ecKey= derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain= new Chain(i);
            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new AChainKey(tmpKey));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(ECKey ecKey) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT);

        Chain chain= new Chain(0);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChildPub(ecKey, chain);
        }
        return new AChainKey(ecKey);
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
        IDerivator derivator= DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagDEFAULT);

        Chain chain= new Chain(0);
        ecKey= derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain= new Chain(i);
            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);

            coinKeys.add(new AChainKey(tmpKey));
        }

        return coinKeys;
    }
}
