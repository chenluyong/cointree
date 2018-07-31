/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

ED25519
*/
package com.bepal.coins.keytree.signer;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.crypto.ed25519.Ed25519EncodedFieldElement;
import com.bepal.coins.crypto.ed25519.Ed25519EncodedGroupElement;
import com.bepal.coins.crypto.ed25519.Ed25519Group;
import com.bepal.coins.crypto.ed25519.Ed25519GroupElement;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.models.ByteArrayData;

public class ED25519 implements ISigner {

    @Override
    public ECSign sign(byte[] priKey, byte[] pubKey, byte[] hash) {
        // Hash the private key to improve randomness.
        // hash only include the last 32 bytes of the private key hash
        // r = H(hash_b,...,hash_2b-1, data) where b=256.
        Ed25519EncodedFieldElement r = new Ed25519EncodedFieldElement(SHAHash.Sha2512(ByteArrayData.concat(priKey, hash)));
        // Reduce size of r since we are calculating mod group order anyway
        Ed25519EncodedFieldElement rModQ = r.modQ();

        // R = rModQ * base point.
        Ed25519GroupElement R = Ed25519Group.BASE_POINT.scalarMultiply(rModQ);
        Ed25519EncodedGroupElement encodedR = R.encode();

        // S = (r + H(encodedR, encodedA, data) * a) mod group order where
        // encodedR and encodedA are the little endian encodings of the group element R and the public key A and
        // a is the lower 32 bytes of hash after clamping.
        final Ed25519EncodedFieldElement h = new Ed25519EncodedFieldElement(SHAHash.Sha2512(ByteArrayData.concat(encodedR.getRaw(), pubKey, hash)));
        final Ed25519EncodedFieldElement hModQ = h.modQ();
        final Ed25519EncodedFieldElement encodedS = hModQ.multiplyAndAddModQ(new Ed25519EncodedFieldElement(priKey), rModQ);

        // Signature is (encodedR, encodedS)
        ECSign ecSign = new ECSign(encodedR.getRaw(), encodedS.getRaw(), (byte) 0xFF);
        return ecSign;
    }

    @Override
    public boolean verify(byte[] pubKey, byte[] hash, ECSign ecSign) {
        // h = H(encodedR, encodedA, data).
        final byte[] rawEncodedR = ecSign.R;
        final byte[] rawEncodedA = pubKey;
        final Ed25519EncodedFieldElement h = new Ed25519EncodedFieldElement(SHAHash.Sha2512(ByteArrayData.concat(rawEncodedR, rawEncodedA, hash)));

        // hReduced = h mod group order
        final Ed25519EncodedFieldElement hModQ = h.modQ();
        // Must compute A.
        final Ed25519GroupElement A = new Ed25519EncodedGroupElement(rawEncodedA).decode();
        A.precomputeForDoubleScalarMultiplication();

        // R = encodedS * B - H(encodedR, encodedA, data) * A
        final Ed25519GroupElement calculatedR = Ed25519Group.BASE_POINT.doubleScalarMultiplyVariableTime(A, hModQ, new Ed25519EncodedFieldElement(ecSign.S));

        // Compare calculated R to given R.
        final byte[] encodedCalculatedR = calculatedR.encode().getRaw();

        final int result = ByteArrayData.isEqualConstantTime(encodedCalculatedR, rawEncodedR);
        return 1 == result;
    }
}
