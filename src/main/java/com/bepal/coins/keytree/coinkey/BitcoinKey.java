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
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.coordinators.SignerCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.models.ByteArrayData;

//import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;

public class BitcoinKey extends ACoinKey {

    private static final int VERSION= 0;
    private static final int TESTVERSION= 111;

    /**
     * net type: main or test
     * */
    private NetType type;

    public BitcoinKey(ECKey ecKey) {
        super(ecKey,0,0);
    }

    public BitcoinKey(ECKey ecKey, NetType netType) {
        super(ecKey,0,0);
        this.type= netType;
    }
    public BitcoinKey(ECKey _ecKey, int _depth, int _path, NetType netType) {
        super(_ecKey,_depth,_path);
        this.type= netType;
    }



    @Override
    public String address() {
        int version= this.type== NetType.MAIN? VERSION: TESTVERSION;

        byte[] bversion;
        bversion = new byte[]{(byte) version};
        byte[] hash= SHAHash.RIPEMD160(SHAHash.Sha2256(this.ecKey.getPubKey()));
        ByteArrayData data = new ByteArrayData();
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

    public static byte[] recoverPubKey(byte[] hash, ECSign ecSign) {
        ISigner signer= SignerCoordinator.getInstance().findSigner(SignerTag.tagSECP256K1);
        return signer.recoverPubKey(hash, ecSign);
    }
}
