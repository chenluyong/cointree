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

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.keytree.KeyTreer;
import com.bepal.coins.keytree.coinkey.BytomKey;
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

public class Bytomer extends ACoiner {

    private static final int BIP44INDEX= 153;


    public Bytomer() {
        super(DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519),BIP44INDEX,NetType.MAIN);
    }

    public Bytomer(NetType netType) {
        super(DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagED25519),BIP44INDEX, netType);
    }


    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagHMAC512_ROOT);
        System.out.println(Hex.toHexString(ecKey.getPriKey()));
        if (ecKey== null)
            return null;

        int secLayer= BIP44INDEX, thdLayer= 0;
        if (this.netType != NetType.MAIN) {
            secLayer= 1;
            thdLayer= BIP44INDEX;
        }

        List<Chain> chains= new ArrayList<>();
        chains.add(new Chain(44, true, 2));
        chains.add(new Chain(secLayer, true, 2));
        chains.add(new Chain(thdLayer, true, 2));

        int depth = 0;
        int path = 0;
        for (Chain chain: chains) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ++depth;
            path = ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(),0,4)).getInt();
        }
        if (ecKey== null)
            return null;

        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return new BytomKey(ecKey, depth, path, this.netType);
    }

    @Override
    public ICoinKey deriveSecChild(ECKey ecKey) {
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0, false, 2);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new BytomKey(ecKey, this.netType);
    }

    @Override
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end) {
        if (ecKey.getPubKey()== null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        Chain chain= new Chain(0, false, 2);
        ecKey= derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new BytomKey(tmpKey, this.netType));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(ECKey ecKey) {
        Chain chain= new Chain(0, false, 2);
        for (int i= 0; i< 2; i++) {
            ecKey= derivator.deriveChildPub(ecKey, chain);
        }
        return new BytomKey(ecKey, this.netType);
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end) {
        Chain chain= new Chain(0, false, 2);
        ecKey= derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys= new ArrayList<>();
        for (int i= start; i<= end; i++) {
            chain.setPath(i);
            ECKey tmpKey= derivator.deriveChildPub(ecKey, chain);

            coinKeys.add(new BytomKey(tmpKey, this.netType));
        }

        return coinKeys;
    }
}
