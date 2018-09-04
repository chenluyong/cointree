package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;
import com.bepal.coins.models.ByteArrayData;

import java.nio.ByteBuffer;
import java.util.Arrays;

public abstract class ACoinKey implements ICoinKey {
    protected HDKey hdKey; // 33 32
    protected NetType netType;


    public ACoinKey(ECKey _ecKey) {
        this.hdKey = new HDKey(_ecKey);
    }
    public ACoinKey(HDKey _hdKey) {
        this.hdKey = _hdKey;
    }

    @Override
    public ECKey base() {
        return this.hdKey.getEcKey();
    }

    public HDKey hdKey() {return this.hdKey; }

    public byte[] toStandardXPrivate() {
        return hdKey.toStandardXPrivate();
    }

    public byte[] toStandardXPublic() {
        return hdKey.toStandardXPublic();
    }

}
