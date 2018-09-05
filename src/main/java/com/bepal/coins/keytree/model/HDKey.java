package com.bepal.coins.keytree.model;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.Hex;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.models.ByteArrayData;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class HDKey{

    ECKey ecKey;
    int depth;
    int path;
    int prvPrefix = 0x0488ADE4; // xprv
    int pubPrefix = 0x0488B21E; // xpub

    public HDKey(ECKey ecKey) {
        this.ecKey = ecKey;
        this.depth = 0;
        this.path = 0;
    }
    public HDKey(ECKey ecKey, int depth, int path) {
        this.ecKey = ecKey;
        this.depth = depth;
        this.path = path;
    }

    /////////////////////  get / set ///////////////////////////

    public ECKey getEcKey() {
        return ecKey;
    }
    public int getDepth() {
        return depth;
    }
    public int getPath() {
        return path;
    }

    public void setEcKey(ECKey ecKey) {
        this.ecKey = ecKey;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public void setPath(int path) {
        this.path = path;
    }

    ///////////////////////////// Prefix //////////////////////////////////
    public int getPrvPrefix() {
        return prvPrefix;
    }
    public void setPrvPrefix(int prvPrefix) {
        this.prvPrefix = prvPrefix;
    }

    public int getPubPrefix() {
        return pubPrefix;
    }
    public void setPubPrefix(int pubPrefix) {
        this.pubPrefix = pubPrefix;
    }

    ///////////////////// function /////////////////////////////

    public String toXPrivate() {
        return Hex.toHexString(Base58.encode(this.toStandardXPrivate()));
    }
    public String toXPublic() {
        return Hex.toHexString(Base58.encode(this.toStandardXPublic()));
    }

    public byte[] toStandardXPrivate() {
        return toStandardXPublic(0x0488ADE4);
    }
    public byte[] toStandardXPrivate(int prefix) {
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

    public byte[] toStandardXPublic() {
        return toStandardXPublic(0x0488B21E);
    }
    public byte[] toStandardXPublic(int prefix) {
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

