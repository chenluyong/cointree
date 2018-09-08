package com.bepal.coins.keytree.model;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.derivator.BitcoinDerivator;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.models.ByteArrayData;

import java.nio.ByteBuffer;

public class HDKey{

    /**
     * 私钥
     */
    ECKey ecKey;
    /**
     * 深度 第几层的意思
     */
    int depth;
    int path;
    int prvPrefix = 0x0488ADE4; // xprv
    int pubPrefix = 0x0488B21E; // xpub

    ///
    private int fingerprint;

    //////////////////////

    public HDKey(byte[] hdKey) throws Exception {
        this(hdKey, new BitcoinDerivator());
    }

    public HDKey(byte[] hdKey, IDerivator derivator) throws Exception {
        ByteArrayData data = new ByteArrayData(hdKey);
        // check sum
        if (!isValid(hdKey)) {
            throw new Exception("非法的分层确定性密钥");
        }
        // prefix 4 byte;
        int head = data.readInt();
        // depth 1 byte
        this.depth = data.readByte();
        // fp 4 byte
        int fingerprint = data.readInt();
        // path 4 byte
        this.path = data.readInt();
        // chain code
        this.ecKey = new ECKey();
        this.ecKey.setChainCode(data.readData(32));
        // key
        byte[] key = data.readData(33);
        if (0 == key[0]) {
            this.ecKey.setPriKey(key);
            if (head != this.prvPrefix) {
                this.prvPrefix = head;
                this.pubPrefix = 0;
            }
        }
        else {
            this.ecKey.setPubKey(key);
            this.pubPrefix = head;
        }
        if (fingerprint != getFingerprint()) {
            throw new Exception("密钥校验位错误，请确认密钥正确项");
        }
        ecKey.setDerivator(derivator);
    }

    public HDKey(ECKey ecKey) {
        this(ecKey,0,0);
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
        return Base58.encode(this.toStandardXPrivate());
    }
    public String toXPublic() {
        return Base58.encode(this.toStandardXPublic());
    }

    public byte[] toStandardXPrivate() {
        return toStandardXPublic(prvPrefix);
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
        return toStandardXPublic(pubPrefix);
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
        if (this.fingerprint == 0)
            fingerprint = ByteBuffer.wrap(ByteArrayData.copyOfRange(SHAHash.sha256hash160(ecKey.getPubKey()), 0, 4)).getInt();
        return fingerprint;
    }

    private boolean isValid(byte[] hdKey) {
        if (hdKey.length != 78 && hdKey.length != 82) {
            return false;
        }
        // check sum;
        if (hdKey.length == 82) {
            byte[] temp = ByteArrayData.copyOfRange(hdKey,0,78);
            byte[] temp_checkSum = ByteArrayData.copyOfRange(hdKey,78,4);
            byte[] checkSum = SHAHash.hash2256Twice(temp);
            if (checkSum == temp_checkSum) {
                return false;
            }
        }
        return true;
    }
}

