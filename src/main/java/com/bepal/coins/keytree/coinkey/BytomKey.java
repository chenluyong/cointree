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
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import sun.nio.ch.Net;

import java.io.ByteArrayOutputStream;

public class BytomKey extends ACoinKey {

    private static final String SEGWITMAIN= "bm";
    private static final String SEGWITTEST= "tm";
    private static final String SEGWITSOLO= "sm";

    /**
     * net type: main or test or solo
     * */
    private NetType type= NetType.MAIN;

    public enum NetType {
        MAIN(0),
        TEST(1),
        SOLO(2);

        private final int val;
        NetType(int val) {
            this.val= val;
        }
    }

    public BytomKey(ECKey ecKey) {
        super(ecKey,0,0);
    }

    public BytomKey(ECKey _ecKey, int _depth, int _path, NetType netType) {
        super(_ecKey,_depth,_path);
        this.type= netType;
    }

    public BytomKey(ECKey ecKey, NetType netType) {
        super(ecKey,0,0);
        this.type= netType;
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

        String segwit= SEGWITMAIN;
        if (this.type== NetType.TEST) {
            segwit= SEGWITTEST;
        } else if (this.type== NetType.SOLO) {
            segwit= SEGWITSOLO;
        }


        return Bech32.Bech32Encode(segwit, stream.toByteArray());
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
