/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

ED25519Derivator
*/
package com.bepal.coins.keytree.infrastructure.derivator;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.crypto.ed25519.Ed25519EncodedFieldElement;
import com.bepal.coins.crypto.ed25519.Ed25519EncodedGroupElement;
import com.bepal.coins.crypto.ed25519.Ed25519Group;
import com.bepal.coins.crypto.ed25519.Ed25519GroupElement;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.infrastructure.coordinators.SeedCoordinator;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.models.ByteArrayData;

public class ED25519Derivator implements IDerivator {

    @Override
    public ECKey deriveChild(ECKey ecKey, Chain chain) {
        byte[] data;
        if (chain.isHardened()) {
            byte[] hData= ByteArrayData.concat("H".getBytes(), ecKey.getPriKey(), chain.getPath());
            data= SHAHash.Hmac512(ecKey.getChainCode(), hData);
            pruneRootScalar(data);

        } else {
            byte[] nData= ByteArrayData.concat("N".getBytes(), ecKey.getPubKey(), chain.getPath());
            data = SHAHash.Hmac512(ecKey.getChainCode(), nData);
            pruneIntermediateScalar(data);

            int sum= 0;
            for (int i= 0; i< 32; i++) {
                byte[] priKey= ecKey.getPriKey();
                int tmpPriKey = priKey[i]< 0? priKey[i]+ 256: priKey[i];
                int tmpData= data[i]< 0? data[i]+ 256: data[i];
                sum= tmpPriKey+ tmpData+ (sum>> 8);
                data[i]= (byte)(sum& 0xFF);
            }
            if ((sum>> 8)!= 0) return null;
        }

        ECKey chiKey= new ECKey();
        chiKey.setPriKey(ByteArrayData.copyOfRange(data, 0, 32));
        chiKey.setChainCode(ByteArrayData.copyOfRange(data, 32, 32));
        return chiKey;
    }

    @Override
    public ECKey deriveChildPub(ECKey ecKey, Chain chain) {
        byte[] hData= ByteArrayData.concat("N".getBytes(), ecKey.getPubKey(), chain.getPath());
        byte[] nData= SHAHash.Hmac512(ecKey.getChainCode(), hData);
        pruneIntermediateScalar(nData);
        Ed25519EncodedFieldElement key= new Ed25519EncodedFieldElement(ByteArrayData.copyOfRange(nData, 0, 32));
        Ed25519GroupElement F= Ed25519Group.BASE_POINT.scalarMultiply(key);
        Ed25519GroupElement P= new Ed25519EncodedGroupElement(ecKey.getPubKey()).decode();
        P= F.addToPub(P);

        ECKey chiKey= new ECKey();
        chiKey.setPubKey(P.encode().getRaw());
        chiKey.setChainCode(ByteArrayData.copyOfRange(nData, 32, 32));
        return chiKey;
    }

    @Override
    public ECKey deriveFromSeed(byte[] seed, SeedTag seedTag) {
        byte[] priMaster= SeedCoordinator.getInstance().deriveMaster(seed, seedTag);
        byte[] priKey= ByteArrayData.copyOfRange(priMaster, 0, 32);
        byte[] chainCode= ByteArrayData.copyOfRange(priMaster, 32, 32);
        pruneRootScalar(priKey);

        ECKey ecKey= new ECKey();
        ecKey.setPriKey(priKey);
        ecKey.setChainCode(chainCode);
        return ecKey;
    }

    @Override
    public byte[] derivePubKey(byte[] priKey) {
        Ed25519EncodedFieldElement key = new Ed25519EncodedFieldElement(priKey);
        Ed25519GroupElement tmpPubKey = Ed25519Group.BASE_POINT.scalarMultiply(key);
        return tmpPubKey.encode().getRaw();
    }

    /**
     * s must be >= 32 bytes long and gets rewritten in place.
     * This is NOT the same pruning as in Ed25519: it additionally clears the third
     * highest bit to ensure subkeys do not overflow the second highest bit.
     */
    private void pruneRootScalar(byte[] s) {
        s[0] &= 248;
        s[31] &= 31; // clear top 3 bits
        s[31] |= 64;// set second highest bit
    }

    /**
     * Clears lowest 3 bits and highest 23 bits of `f`.
     */
    private void pruneIntermediateScalar(byte[] f) {
        f[0] &= 248; // clear bottom 3 bits
        f[29] &= 1;  // clear 7 high bits
        f[30] = 0;  // clear 8 bits
        f[31] = 0;   // clear 8 bits
    }
}
