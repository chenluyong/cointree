/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

EthereumKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.models.ByteArrayData;

import static com.bepal.coins.keytree.signer.Secp256k1.CURVE;

public class EthereumKey implements ICoinKey {
    private ECKey ecKey;

    public EthereumKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }

    @Override
    public ECKey base() {
        return this.ecKey;
    }

    @Override
    public String address() {
        byte[] point= CURVE.getCurve().decodePoint(this.ecKey.getPubKey()).getEncoded(false);
        byte[] pubKey= ByteArrayData.copyOfRange(point, 1, 64);
        byte[] data=  ByteArrayData.copyOfRange(SHAHash.Keccak256(pubKey), 12, 20);
        return "0x"+ Hex.toHexString(data);
    }

    @Override
    public String publicKey() {
        return null;
    }

    @Override
    public String privateKey() {
        return null;
    }

    @Override
    public ECSign sign(byte[] hash) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1);
        return signer.sign(this.ecKey.getPriKey(), this.ecKey.getPubKey(), hash);
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1);
        return signer.verify(this.ecKey.getPubKey(), hash, ecSign);
    }
}
