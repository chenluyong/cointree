package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.bepal.coins.keytree.infrastructure.interfaces.ICoin.NetType.MAIN;

public abstract class ACoiner implements ICoiner {

    /////////////////internal class////////////////

    public class HDKey{
        public ECKey getEcKey() {
            return ecKey;
        }
        public int getDepth() {
            return depth;
        }
        public int getPath() {
            return path;
        }

        ECKey ecKey;
        int depth = 0;
        int path = 0;

        public HDKey(ECKey ecKey, int depth, int path) {
            this.ecKey = ecKey;
            this.depth = depth;
            this.path = path;
        }
    }

    ///////////////// params ///////////////////////

    protected IDerivator derivator;
    // bip44 coin type
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    protected int coinType;

    /**
     * net type: main or test
     * */
    protected NetType netType;


    ///////////////////// function ///////////////////////
    public ACoiner(IDerivator _derivator,int _coinType, NetType _netType) {
        this.derivator = _derivator;
        this.coinType = _coinType;
        this.netType = _netType;
    }


    protected HDKey deriveBip44(ECKey _ecKey) {
        if (_ecKey == null) return null;

        int secLayer= this.coinType, thdLayer= 0;
        if (netType != MAIN) {
            secLayer= 1;
            thdLayer= this.coinType;
        }

        List<Chain> chains= new ArrayList<>();
        chains.add(new Chain(44, true));
        chains.add(new Chain(secLayer, true));
        chains.add(new Chain(thdLayer, true));

        int depth = 0;
        int path = 0;
        for (Chain chain: chains) {
            _ecKey= this.derivator.deriveChild(_ecKey, chain);
            ++depth;
            path = ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(),0,4)).getInt();
        }
        if (_ecKey== null) return null;

        _ecKey.setPubKey(this.derivator.derivePubKey(_ecKey.getPriKey()));
        return new HDKey(_ecKey, depth, path);
    }

}
