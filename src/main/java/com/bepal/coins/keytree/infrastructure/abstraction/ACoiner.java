package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.keytree.config.CoinKeyFactory;
import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ACoiner implements ICoiner {
    ///////////////// params ///////////////////////

    protected IDerivator derivator;

    protected CoinConfig config;

    ///////////////////// construct ///////////////////////

    public ACoiner(CoinConfig config) {
        this.config = config;
        this.derivator = DeriveCoordinator.getInstance().findDerivator(this.config.getDeriveTag());
    }

    ///////////////////// function ///////////////////////
    @Override
    public ICoinKey deriveBip44(byte[] seed) {
        ECKey ecKey = derivator.deriveFromSeed(seed, this.config.getSeedTag());
        if (ecKey == null) return null;

        int secLayer = (int) this.config.getBip44(), thdLayer = 0;
        if (this.config.getNetType() != ICoin.NetType.MAIN) {
            secLayer = 1;
            thdLayer = (int) this.config.getBip44();
        }

        List<Chain> chains = new ArrayList<>();
        chains.add(getChain(44,true));
        chains.add(getChain(secLayer,true));
        chains.add(getChain(thdLayer,true));

        int depth = 0;
        int path = 0;
        for (Chain chain : chains) {
            ecKey = derivator.deriveChild(ecKey, chain);
            ++depth;
            path = ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(), 0, 4)).getInt();
        }
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        return this.base(new HDKey(ecKey, depth, path));
    }

    @Override
    public ICoinKey deriveSecChild(HDKey hdKey) {
        ECKey ecKey = hdKey.getEcKey();
        if (null == ecKey.getPubKey()) {
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }

        int depth = hdKey.getDepth();
        Chain chain = getChain(0);
        for (int i = 0; i < 2; ++i, ++depth) {
            ecKey = derivator.deriveChild(ecKey, chain);
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }
        return this.base(new HDKey(ecKey, depth, 0));
    }


    @Override
    public List<ICoinKey> deriveSecChildRange(HDKey hdKey, int start, int end) {
        ECKey ecKey = hdKey.getEcKey();
        if (null == ecKey.getPubKey()) {
            ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));
        }

        Chain chain = getChain(0);
        ecKey = derivator.deriveChild(ecKey, chain);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        List<ICoinKey> coinKeys = new ArrayList<>();
        for (int pos = start; pos <= end; ++pos) {
            chain.setPath(pos);
            ECKey tmpKey = derivator.deriveChild(ecKey, chain);
            tmpKey.setPubKey(derivator.derivePubKey(tmpKey.getPriKey()));

            coinKeys.add(this.base(new HDKey(tmpKey, hdKey.getDepth() + 1, pos)));
        }

        return coinKeys;
    }

    @Override
    public ICoinKey deriveSecChildPub(HDKey hdKey) {
        ECKey ecKey = hdKey.getEcKey();
        Chain chain = getChain(0);
        int depth = hdKey.getDepth();
        for (int i = 0; i < 2; ++i, ++depth) {
            ecKey = derivator.deriveChildPub(ecKey, chain);
        }
        return this.base(new HDKey(ecKey, depth, 0));
    }

    @Override
    public List<ICoinKey> deriveSecChildRangePub(HDKey hdKey, int start, int end) {
        ECKey ecKey = hdKey.getEcKey();
        Chain chain = getChain(0);
        ecKey = derivator.deriveChildPub(ecKey, chain);

        List<ICoinKey> coinKeys = new ArrayList<>();
        for (int pos = start; pos <= end; ++pos) {
            chain.setPath(pos);
            ECKey tmpKey = derivator.deriveChildPub(ecKey, chain);
            coinKeys.add(this.base(new HDKey(tmpKey, hdKey.getDepth() + 1, pos)));
        }

        return coinKeys;
    }

    protected Chain getChain(int path) {
        return getChain(path, false);
    }
    protected Chain getChain(int path, boolean hardened) {
        return new Chain(path, hardened);
    }

    private ICoinKey base(HDKey hdKey) {
        return CoinKeyFactory.get(config.getCoinTag(), hdKey);
    }
}
