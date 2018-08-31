package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.Hex;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.models.ByteArrayData;

import javax.swing.plaf.synth.SynthTextAreaUI;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.Arrays;

public abstract class ACoinKey implements ICoinKey {
    protected ECKey ecKey; // 33 32
    protected int depth = 0; // 1
    protected long path = 0; // 4
    // hdkey head  (example: xpub\xprv)


    public ACoinKey(ECKey _ecKey, int _depth, int _path) {
        this.ecKey = _ecKey;
        this.depth = _depth;
        this.path = _path;
    }



    @Override
    public ECKey base() {
        return ecKey;
    }


    ///////////////////HDKey////////////////////
    public byte[] toStandardXPrivate(int prefix) {
        if (0 == prefix) {
            prefix = 0x0488ADE4;
        }
        ByteArrayData data = new ByteArrayData();
        data.appendIntLE(prefix);
        data.appendByte(this.depth);
        data.appendIntLE(this.getFingerprint());
        data.appendIntLE(this.path);
        data.putBytes(this.ecKey.getChainCode());
        byte[] privateKey = this.ecKey.getPriKey();
        if (null == privateKey) {
            return null;
        }
        if (privateKey.length == 32) {
            data.appendByte(0);
        }
        data.putBytes(privateKey);
        byte[] checkSum = SHAHash.hash2256Twice(data.toBytes());
        data.putBytes(ByteArrayData.copyOfRange(checkSum,0,4));
        return data.toBytes();
    }

    public byte[] toStandardXPublic(int prefix) {
        if (0 == prefix) {
            prefix = 0x0488B21E;
        }
        ByteArrayData data = new ByteArrayData();
        data.appendIntLE(prefix);
        data.appendByte(this.depth);
        data.appendIntLE(this.getFingerprint());
        data.appendIntLE(this.path);
        data.putBytes(this.ecKey.getChainCode());
        byte[] publicKey = this.ecKey.getPubKey();
        if (null == publicKey) {
            return null;
        }
        if (publicKey.length == 32) {
            data.appendByte(0);
        }
        data.putBytes(publicKey);
        byte[] checkSum = SHAHash.hash2256Twice(data.toBytes());
        data.putBytes(ByteArrayData.copyOfRange(checkSum,0,4));

        return data.toBytes();

    }


    private int getFingerprint() {
        return ByteBuffer.wrap(Arrays.copyOfRange(SHAHash.sha256hash160(ecKey.getPubKey()), 0, 4)).getInt();
    }

}
