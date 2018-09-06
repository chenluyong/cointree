package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.keytree.infrastructure.coordinators.SeedCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;
import com.bepal.coins.models.ByteArrayData;

import java.nio.ByteBuffer;
import java.util.Arrays;

public abstract class ADerivator implements IDerivator {

    public HDKey deriveChild(HDKey hdKey, Chain chain) {
        ECKey ecKey = hdKey.getEcKey();
        if (null != ecKey.getPriKey()) {
            ecKey = deriveChild(ecKey, chain);
            ecKey.setPubKey(this.derivePubKey(ecKey.getPriKey()));
        }
        else {
            ecKey = deriveChildPub(ecKey, chain);
        }
        return new HDKey(ecKey, hdKey.getDepth() + 1,
                ByteBuffer.wrap(Arrays.copyOfRange(chain.getPath(), 0, 4)).getInt());
    }

    @Override
    public HDKey deriveFromSeed(byte[] seed, SeedTag seedTag) {
        byte[] priMaster = SeedCoordinator.getInstance().deriveMaster(seed, seedTag);

        ECKey ecKey = new ECKey(ByteArrayData.copyOfRange(priMaster, 0, 32),
                null, ByteArrayData.copyOfRange(priMaster, 32, 32));

        return new HDKey(ecKey,0,0);
    }
}
