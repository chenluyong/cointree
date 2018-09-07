package com.bepal.coins.keytree.infrastructure.abstraction;

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.keytree.model.HDKey;

public abstract class ACoinKey implements ICoinKey {
    protected HDKey hdKey; // 33 32
    protected CoinConfig config;

    public ACoinKey(ECKey _ecKey, CoinConfig config) {
        this.hdKey = new HDKey(_ecKey);
        this.config = config;
    }
    public ACoinKey(HDKey _hdKey, CoinConfig config) {
        this.hdKey = _hdKey;
        this.config = config;
    }


    //////////////////////// base class ////////////////////////////////
    @Override
    public ECKey base() {
        return this.hdKey.getEcKey();
    }


    @Override
    public String publicKey() {
        return Hex.toHexString(this.hdKey.getEcKey().getPubKey());
    }

    @Override
    public String privateKey() {
        return Hex.toHexString(this.hdKey.getEcKey().getPriKey());
    }

    @Override
    public ECSign sign(byte[] hash) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(config.getSignerTag());
        return signer.sign(this.base().getPriKey(), this.hdKey.getEcKey().getPubKey(), hash);
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(config.getSignerTag());
        return signer.verify(this.base().getPubKey(), hash, ecSign);
    }

    //////////////////////// new function ///////////////////////////////

    public HDKey hdKey() {return this.hdKey; }

    public CoinConfig config() {return this.config;}

    public byte[] toStandardXPrivate() {
        return hdKey.toStandardXPrivate();
    }

    public byte[] toStandardXPublic() {
        return hdKey.toStandardXPublic();
    }


}
