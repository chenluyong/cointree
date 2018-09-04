package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class ACoiner implements ICoiner {
    ///////////////// params ///////////////////////

    protected IDerivator derivator;


    protected Config config;

    ///////////////////// construct ///////////////////////

    public ACoiner(Config config) {
        this.config = config;
        this.derivator = DeriveCoordinator.getInstance().findDerivator(this.config.deriveTag);
    }

    ///////////////////// function ///////////////////////
    @Override
    public HDKey deriveBip44(byte[] seed) {
        System.out.println(Hex.toHexString(seed));
        ECKey ecKey = derivator.deriveFromSeed(seed, this.config.seedTag);
        System.out.println(Hex.toHexString(ecKey.getPriKey()));
        if (ecKey == null) return null;

        int secLayer = (int) this.config.bip44, thdLayer = 0;
        if (this.config.netType != NetType.MAIN) {
            secLayer = 1;
            thdLayer = (int) this.config.bip44;
        }

        List<Chain> chains = new ArrayList<>();
        chains.add(new Chain(44, true));
        chains.add(new Chain(secLayer, true));
        chains.add(new Chain(thdLayer, true));

        int depth = 0;
        int path = 0;
        for (Chain chain : chains) {
            ecKey = derivator.deriveChild(ecKey, chain);
            System.out.println("Chain:" + Hex.toHexString(ecKey.getPriKey()));
            ++depth;
            path = ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(), 0, 4)).getInt();
        }
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return new HDKey(ecKey, depth, path);
    }

    @Override
    public HDKey deriveSecChild(HDKey hdKey) {
        ECKey ecKey = hdKey.getEcKey();
        if (ecKey.getPubKey() == null) ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        int depth = hdKey.getDepth();
        Chain chain = new Chain(0);
        for (int i = 0; i < 2; i++, ++depth) {
            ecKey = derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return new HDKey(ecKey, depth, 0);
    }


    @Override
    public List<HDKey> deriveSecChildRange(HDKey hdKey, int start, int end) {
        ECKey ecKey = hdKey.getEcKey();
        if (null == ecKey.getPubKey()) {
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }

        Chain chain = new Chain(0);
        ecKey = derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<HDKey> coinKeys = new ArrayList<>();
        for (int pos = start; pos <= end; ++pos) {
            chain.setPath(pos);
            ECKey tmpKey = derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(new HDKey(tmpKey, hdKey.getDepth() + 1, pos));
        }

        return coinKeys;
    }

    @Override
    public HDKey deriveSecChildPub(HDKey hdKey) {
        ECKey ecKey = hdKey.getEcKey();
        Chain chain = new Chain(0);
        int depth = hdKey.getDepth();
        for (int i = 0; i < 2; ++i, ++depth) {
            ecKey = derivator.deriveChildPub(ecKey, chain);
        }
        return new HDKey(ecKey, depth, 0);
    }

    @Override
    public List<HDKey> deriveSecChildRangePub(HDKey hdKey, int start, int end) {
        ECKey ecKey = hdKey.getEcKey();
        Chain chain = new Chain(0);
        ecKey = derivator.deriveChildPub(ecKey, chain);

        List<HDKey> coinKeys = new ArrayList<>();
        for (int i = start; i <= end; i++) {
            chain.setPath(i);
            ECKey tmpKey = derivator.deriveChildPub(ecKey, chain);
            coinKeys.add(new HDKey(tmpKey, hdKey.getDepth() + 1, start));
        }

        return coinKeys;
    }
}
