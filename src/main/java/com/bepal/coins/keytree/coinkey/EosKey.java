/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

EosKey
*/
package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

public class EosKey implements ICoinKey {
    private ECKey ecKey;

    public EosKey(ECKey ecKey) {
        this.ecKey= ecKey;
    }

    @Override
    public ECKey base() {
        return this.ecKey;
    }

    @Override
    public String address() {
        return publicKey();
    }

    @Override
    public String publicKey() {
        return "EOS"+ GrapheneSerializer.serializePubKey(this.ecKey.getPubKey());
    }

    @Override
    public String privateKey() {
        return GrapheneSerializer.wifPriKey(this.ecKey.getPriKey());
    }

    @Override
    public ECSign sign(byte[] hash) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1NONCE);
        return signer.sign(this.ecKey.getPriKey(), this.ecKey.getPubKey(), hash);
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1NONCE);
        return signer.verify(this.ecKey.getPubKey(), hash, ecSign);
    }
}
