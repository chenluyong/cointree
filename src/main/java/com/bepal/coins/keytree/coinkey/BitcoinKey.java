/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

BitcoinKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.models.ByteArrayData;

import java.util.Arrays;

public class BitcoinKey implements ICoinKey {
    private ECKey ecKey;
    private int VERSION= 0;

    public BitcoinKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }

    @Override
    public ECKey base() {
        return ecKey;
    }

    @Override
    public String address() {
        byte[] hash= SHAHash.RIPEMD160(SHAHash.Sha2256(this.ecKey.getPubKey()));

        ByteArrayData data = new ByteArrayData();
        byte[] bversion;
        if (VERSION <= 255) {
            bversion = new byte[]{(byte) VERSION};
        } else {
            bversion = new byte[]{(byte) (VERSION >> 8 & 0xFF), (byte) (VERSION & 0xFF)};
        }
        data.putBytes(bversion);
        data.putBytes(hash);
        byte[] checksum = SHAHash.hash2256Twice(data.toBytes());
        data.putBytes(checksum, 4);
        return Base58.encode(data.toBytes());
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

    public byte[] recoverPubKey(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1);
        return signer.recoverPubKey(hash, ecSign);
    }
}
