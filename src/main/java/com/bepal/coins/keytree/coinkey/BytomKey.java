/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

BytomKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Bech32;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

import java.io.ByteArrayOutputStream;

public class BytomKey implements ICoinKey {
    private ECKey ecKey;

    private final String SEGWITMAIN= "bm";
    private final String SEGWITTEST= "tm";
    private final String SEGWITSOLO= "sm";

    public BytomKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }


    @Override
    public ECKey base() {
        return this.ecKey;
    }

    @Override
    public String address() {
        byte[] data= SHAHash.RIPEMD160(this.ecKey.getPubKey());
        byte[] bData= Bech32.ConvertBits(data, (byte) 8, (byte) 5, true);
        ByteArrayOutputStream stream= new ByteArrayOutputStream();
        stream.write(0);
        stream.write(bData, 0, bData.length);

        return Bech32.Bech32Encode(SEGWITMAIN, stream.toByteArray());
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
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagED25519);
        return signer.sign(this.ecKey.getPriKey(), this.ecKey.getPubKey(), hash);
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagED25519);
        return signer.verify(this.ecKey.getPubKey(), hash, ecSign);
    }
}
