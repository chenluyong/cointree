package com.bepal.coins.keytree.infrastructure.derivator;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.abstraction.ADerivator;
import com.bepal.coins.keytree.infrastructure.coordinators.SeedCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.signer.Secp256r1;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.Chain;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.models.ByteArrayData;
import com.bepal.coins.utils.BigIntUtil;
import com.bepal.coins.utils.ErrorTool;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Secp256r1Derivator extends ADerivator {

    @Override
    public ECKey deriveChild(ECKey ecKey, Chain chain) {
        ByteBuffer data = ByteBuffer.allocate(37);
        if (chain.isHardened()) {
            data.put((byte) 0);
            data.put(ecKey.getPriKey());
        } else {
            data.put(ecKey.getPubKey());
        }
        data.put(chain.getPath());
        byte[] i = SHAHash.Hmac512(ecKey.getChainCode(), data.array());
        ErrorTool.checkState(i.length == 64, i.length);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        BigInteger ilInt = new BigInteger(1, il);
        ErrorTool.assertLessThanN(Secp256r1.CURVE.getN(), ilInt, "Illegal derived key: I_L >= n");
        final BigInteger priv = new BigInteger(1, ecKey.getPriKey());
        BigInteger ki = priv.add(ilInt).mod(Secp256r1.CURVE.getN());
        ErrorTool.assertNonZero(ki, "Illegal derived key: derived private key equals 0.");

        ECKey chiKey = new ECKey(BigIntUtil.bigIntegerToBytesLE(ki, 32),
                null,chainCode,this);
        return chiKey;
    }

    @Override
    public ECKey deriveChildPub(ECKey ecKey, Chain chain) {
        ByteBuffer data = ByteBuffer.allocate(37);
        data.put(ecKey.getPubKey());
        data.put(chain.getPath());
        byte[] i = SHAHash.Hmac512(ecKey.getChainCode(), data.array());
        ErrorTool.checkState(i.length == 64, i.length);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        BigInteger ilInt = new BigInteger(1, il);
        ErrorTool.assertLessThanN(Secp256r1.CURVE.getN(), ilInt, "Illegal derived key: I_L >= n");
        ECPoint Ki = publicPointFromPrivate(ilInt).add(Secp256r1.CURVE.getCurve().decodePoint(ecKey.getPubKey()));

        ECKey chiKey = new ECKey(null,
                Ki.getEncoded(true),chainCode,this);
        return chiKey;
    }


    @Override
    public byte[] derivePubKey(byte[] priKey) {
        BigInteger priInt = new BigInteger(1, priKey);
        if (priInt.bitLength() > Secp256r1.CURVE.getN().bitLength()) {
            priInt = priInt.mod(Secp256r1.CURVE.getN());
        }
        ECPoint ecPoint = new FixedPointCombMultiplier().multiply(Secp256r1.CURVE.getG(), priInt);
        return ecPoint.getEncoded(true);
    }

    /**
     * Returns public key point from the given private key. To convert a byte array into a BigInteger, use <tt>
     * new BigInteger(1, bytes);</tt>
     */
    private static ECPoint publicPointFromPrivate(BigInteger privKey) {
        /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group order,
         * but that could change in future versions.
         */
        if (privKey.bitLength() > Secp256r1.CURVE.getN().bitLength()) {
            privKey = privKey.mod(Secp256r1.CURVE.getN());
        }
        return new FixedPointCombMultiplier().multiply(Secp256r1.CURVE.getG(), privKey);
    }
}
