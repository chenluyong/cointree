/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

Secp256k1Nonce
*/
package com.bepal.coins.keytree.infrastructure.signer;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.models.ByteArrayData;
import com.bepal.coins.utils.ErrorTool;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class Secp256k1Nonce implements ISigner {

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /**
     * The parameters of the secp256r1 curve that Bitcoin uses.
     */
    private static ECDomainParameters CURVE;
    private static BigInteger HALF_CURVE_ORDER;

    static {
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = CURVE.getN().shiftRight(1);
    }

    private static BigInteger CURVE_Q = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    @Override
    public ECSign sign(byte[] priKey, byte[] pubKey, byte[] hash) {
        BigInteger privAsBI= new BigInteger(1, priKey);
        int nonce = 0;

        ECSign signature = null;
        while (true) {
            signature = deterministicGenerateK(hash, privAsBI, nonce++);
            BigInteger r = signature.getRBigInt();
            BigInteger s = signature.getSBigInt();
            if (s.compareTo(HALF_CURVE_ORDER) > 0) {//  Secp256k1Param.HALF_CURVE_ORDER) > 0) {
                signature.setSBigInt(CURVE.getN().subtract(s));//   Secp256k1Param.n.subtract(checker.s);
            }
            s = signature.getSBigInt();
            if (r.toByteArray().length == 32 && s.toByteArray().length == 32) {
                break;
            }
        }
        for (int i = 0; i < 4; i++) {
            byte[] recovered = recoverPubKey(hash, signature, (byte) i);
            if (Arrays.equals(pubKey, recovered)) {
                signature.V = (byte) i;
                break;
            }
        }
        if (signature.V < 0) {
            throw new IllegalStateException("could not find recid. Was this data signed with this key?");
        }
        return signature;
    }

    @Override
    public boolean verify(byte[] pubKey, byte[] hash, ECSign ecSign) {
        byte recId = ecSign.V;
        ErrorTool.checkArgument(recId >= 0, "recId must be positive");
        ErrorTool.checkArgument(ecSign.getRBigInt().compareTo(BigInteger.ZERO) >= 0, "r must be positive");
        ErrorTool.checkArgument(ecSign.getSBigInt().compareTo(BigInteger.ZERO) >= 0, "s must be positive");
        ErrorTool.checkNotNull(hash);
        // 1.0 For j from 0 to h (h == recId here and the loop is outside this
        // function)
        // 1.1 Let x = r + jn

        BigInteger n = CURVE.getN();//Secp256k1Param.n; // EcCurve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = ecSign.getRBigInt().add(i.multiply(n));
        // 1.2. Convert the integer x to an octet string X of length mlen using
        // the conversion routine
        // specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen =
        // ⌈m/8⌉.
        // 1.3. Convert the octet string (16 set binary digits)||X to an elliptic
        // curve point R using the
        // conversion routine specified in Section 2.3.4. If this conversion
        // routine outputs "invalid", then
        // do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed
        // public key.

        BigInteger prime = CURVE_Q; // Bouncy Castle is not consistent about
        // the letter it uses for the prime.
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes
            // place modulo Q.
            return false;
        }
        // Compressed keys require you to know an extra bit of data about the
        // y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        // 1.4. If nR != point at infinity, then do another iteration of Step 1
        // (callers responsibility).
        if (!R.multiply(n).isInfinity()) {
            return false;
        }
        // 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature
        // verification.
        BigInteger e = new BigInteger(1, hash);
        // 1.6. For k from 1 to 2 do the following. (loop is outside this function
        // via iterating recId)
        // 1.6.1. Compute a candidate public key as:
        // Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this
        // into the following:
        // Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z +
        // e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking
        // the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 =
        // 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = ecSign.getRBigInt().modInverse(n);
        BigInteger srInv = rInv.multiply(ecSign.getSBigInt()).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv); //Secp256k1Param.G, eInvrInv, R, srInv);
        return Arrays.equals(pubKey, q.getEncoded(true));
    }

    @Override
    public byte[] recoverPubKey(byte[] hash, ECSign ecSign) {
        return recoverPubKey(hash, ecSign, ecSign.V);
    }

    private static byte[] recoverPubKey(byte[] messageSigned, ECSign ecSign, byte recId) {
        ErrorTool.checkArgument(recId >= 0, "recId must be positive");
        ErrorTool.checkArgument(ecSign.getRBigInt().compareTo(BigInteger.ZERO) >= 0, "r must be positive");
        ErrorTool.checkArgument(ecSign.getSBigInt().compareTo(BigInteger.ZERO) >= 0, "s must be positive");
        ErrorTool.checkNotNull(messageSigned);
        // 1.0 For j from 0 to h (h == recId here and the loop is outside this
        // function)
        // 1.1 Let x = r + jn

        BigInteger n = CURVE.getN();// Secp256k1Param.n; // EcCurve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = ecSign.getRBigInt().add(i.multiply(n));
        // 1.2. Convert the integer x to an octet string X of length mlen using
        // the conversion routine
        // specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen =
        // ⌈m/8⌉.
        // 1.3. Convert the octet string (16 set binary digits)||X to an elliptic
        // curve point R using the
        // conversion routine specified in Section 2.3.4. If this conversion
        // routine outputs "invalid", then
        // do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed
        // public key.

        BigInteger prime = CURVE_Q; // Bouncy Castle is not consistent about
        // the letter it uses for the prime.
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes
            // place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the
        // y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        // 1.4. If nR != point at infinity, then do another iteration of Step 1
        // (callers responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        // 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature
        // verification.
        BigInteger e = new BigInteger(1, messageSigned);
        // 1.6. For k from 1 to 2 do the following. (loop is outside this function
        // via iterating recId)
        // 1.6.1. Compute a candidate public key as:
        // Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this
        // into the following:
        // Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z +
        // e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking
        // the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 =
        // 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = ecSign.getRBigInt().modInverse(n);
        BigInteger srInv = rInv.multiply(ecSign.getSBigInt()).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv); //  Secp256k1Param.G, eInvrInv, R, srInv);
        return q.getEncoded(true);
    }

    private ECSign deterministicGenerateK(byte[] hash, BigInteger prv, int nonce) {
        byte[] newhash = hash;
        if (nonce > 0) {
            byte[] arr = new byte[]{(byte) 0x81};//secureRandom.generateSeed(nonce);
            newhash = SHAHash.Sha2256(ByteArrayData.concat(hash, arr));
        }

        byte[] dBytes = prv.toByteArray();

        // Step b
        byte[] v = new byte[32];
        Arrays.fill(v, (byte) 0x01);

        // Step c
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) 0x00);

        // Step d
        ByteArrayData bwD = new ByteArrayData(32 + 1 + 32 + 32);
        bwD.putBytes(v);
        bwD.appendByte((byte) 0x00);
        bwD.putBytes(dBytes);
        bwD.putBytes(newhash);
        k = SHAHash.Hmac256(k, bwD.toBytes());

        // Step e
        v = SHAHash.Hmac256(k, v);

        // Step f
        ByteArrayData bwF = new ByteArrayData(32 + 1 + 32 + 32);
        bwF.putBytes(v);
        bwF.appendByte((byte) 0x01);
        bwF.putBytes(dBytes);
        bwF.putBytes(newhash);
        k = SHAHash.Hmac256(k, bwF.toBytes());

        // Step g
        v = SHAHash.Hmac256(k, v);

        // Step H2b
        v = SHAHash.Hmac256(k, v);

        BigInteger t = new BigInteger(1, v);

        ECSign ecSign = new ECSign();
        // Step H3, repeat until T is within the interval [1, Secp256k1Param.n - 1]
        while ((t.signum() <= 0) || (t.compareTo(CURVE.getN()) >= 0) || !checkSignature(hash, prv, t, ecSign)) {
            ByteArrayData bwH = new ByteArrayData(32 + 1);
            bwH.putBytes(v);
            bwH.appendByte((byte) 0x00);
            k = SHAHash.Hmac256(k, bwH.toBytes());
            v = SHAHash.Hmac256(k, v);

            // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
            // Step H2b again
            v = SHAHash.Hmac256(k, v);

            t = new BigInteger(v);
        }
        return ecSign;
    }

    private boolean checkSignature(byte[] hash, BigInteger privKey, BigInteger k, ECSign ecSign) {
        BigInteger e = new BigInteger(1, hash);

        ECPoint Q = CURVE.getG().multiply(k);// Secp256k1Param.G, k);
        if (Q.isInfinity()) {
            return false;
        }

        BigInteger r = Q.getX().toBigInteger().mod(CURVE.getN());// Secp256k1Param.n );
        if (r.signum() == 0) {
            return false;
        }


        BigInteger s = k.modInverse(CURVE.getN())// Secp256k1Param.n)
                .multiply(e.add(privKey.multiply(r)))
                .mod(CURVE.getN());// Secp256k1Param.n);

        if (s.signum() == 0) {
            return false;
        }

        ecSign.fromRS(r, s);
        return true;
    }

    /**
     * Decompress a compressed public key (x co-ord and low-bit of y-coord).
     */
    public static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }
}
