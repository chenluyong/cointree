package com.bepal.coins.keytree.model;

import com.bepal.coins.crypto.Hex;
import com.bepal.coins.models.ByteArrayData;
import com.bepal.coins.utils.BigIntUtil;
import org.spongycastle.asn1.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.text.MessageFormat;

public class ECSign {

    public byte[] R;
    public byte[] S;
    public byte V;

    public ECSign() {
    }

    public ECSign(BigInteger[] data) {
        R = BigIntUtil.bigIntegerToBytesLE(data[0], 32);
        S = BigIntUtil.bigIntegerToBytesLE(data[1], 32);
        V = -1;
    }

    private ECSign(byte[] data) {
        R = ByteArrayData.copyOfRange(data, 1, 32);
        S = ByteArrayData.copyOfRange(data, 33, 32);
        V = data[0];
    }

    public ECSign(byte[] data, byte v) {
        R = ByteArrayData.copyOfRange(data, 0, 32);
        S = ByteArrayData.copyOfRange(data, 32, 32);
        V = v;
    }

    public ECSign(byte[] r, byte[] s, byte v) {
        R = r;
        S = s;
        V = v;
    }


    public static ECSign fromData(byte[] data) {
        byte[] r = ByteArrayData.copyOfRange(data, 1, 32);
        byte[] s = ByteArrayData.copyOfRange(data, 33, 32);
        byte v = data[0];
        //表示是否压缩
        if (v >= 27) {
            v -= 27;
            //表示公钥是否压缩
            if (v >= 4) {
                v -= 4;
            }
        }
        return new ECSign(r, s, v);
    }

    public static ECSign fromSignNoV(byte[] data) {
        return new ECSign(data, (byte) 0xFF);
    }

    public static ECSign fromSignDer(byte[] data) {
        ASN1InputStream decoder = null;
        try {
            decoder = new ASN1InputStream(data);
            final ASN1Primitive seqObj = decoder.readObject();
            if (seqObj == null) {
                throw new IllegalArgumentException("Reached past end of ASN.1 stream.");
            }
            if (!(seqObj instanceof DLSequence)) {
                throw new IllegalArgumentException("Read unexpected class: " + seqObj.getClass().getName());
            }
            final DLSequence seq = (DLSequence) seqObj;
            ASN1Integer r, s;
            try {
                r = (ASN1Integer) seq.getObjectAt(0);
                s = (ASN1Integer) seq.getObjectAt(1);
            } catch (ClassCastException e) {
                throw new IllegalArgumentException(e);
            }
            // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
            // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
            BigInteger[] arr = new BigInteger[2];
            arr[0] = r.getPositiveValue();
            arr[1] = s.getPositiveValue();
            return new ECSign(arr);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (decoder != null) {
                try {
                    decoder.close();
                } catch (IOException x) {
                }
            }
        }
    }

    public void fromRS(BigInteger r, BigInteger s) {
        R = BigIntUtil.bigIntegerToBytesLE(r, 32);
        S = BigIntUtil.bigIntegerToBytesLE(s, 32);
        V = -1;
    }

    public byte[] toDer() {
        // Usually 70-72 bytes.
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
            DERSequenceGenerator seq = new DERSequenceGenerator(bos);
            seq.addObject(new ASN1Integer(getRBigInt()));
            seq.addObject(new ASN1Integer(getSBigInt()));
            seq.close();
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] toData() {
        ByteArrayData data = new ByteArrayData();
        data.appendByte(V);
        data.putBytes(R);
        data.putBytes(S);
        return data.toBytes();
    }

    public byte[] toDataNoV() {
        ByteArrayData data = new ByteArrayData();
        data.putBytes(R);
        data.putBytes(S);
        return data.toBytes();
    }

    public String toHex() {
        if (V == -1) {
            return Hex.toHexString(toDataNoV());
        }
        return Hex.toHexString(toData());
    }

    public byte[] encoding(boolean compressed) {
        ByteArrayData data = new ByteArrayData();
        data.appendByte(getV(compressed));
        data.putBytes(R);
        data.putBytes(S);
        return data.toBytes();
    }

    /**
     * V的处理
     * @param compressed 该值表示公钥是否压缩过 ETH默认不压缩的应该传false 其他
     */
    private byte getV(boolean compressed) {
        return (byte) (V + 27 + (compressed ? 4 : 0));
    }

    public byte getEthV() {
        return getV(false);
    }

    public BigInteger getRBigInt() {
        return new BigInteger(1, R);
    }

    public BigInteger getSBigInt() {
        return new BigInteger(1, S);
    }

    public void setSBigInt(BigInteger s) {
        S = BigIntUtil.bigIntegerToBytesLE(s, 32);
    }

    @Override
    public String toString() {
        return MessageFormat.format("\nR:{0} \nS:{1} \nV:{2}", Hex.toHexString(R), Hex.toHexString(S), V);
    }
}
