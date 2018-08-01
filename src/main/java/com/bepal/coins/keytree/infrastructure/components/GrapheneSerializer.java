package com.bepal.coins.keytree.infrastructure.components;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;

public class GrapheneSerializer {

    public static String wifPriKey(byte[] priKey) {
        byte[] toDigest= new byte[priKey.length+ 1];

        toDigest[0]= (byte)0x80;
        System.arraycopy(priKey, 0, toDigest, 1, priKey.length);
        byte[] digest= SHAHash.hash2256Twice(toDigest);

        byte[] result= new byte[priKey.length+ 5];
        System.arraycopy(toDigest, 0, result, 0, toDigest.length);
        System.arraycopy(digest, 0, result, toDigest.length, 4);
        return Base58.encode(result);
    }

    public static String serializePubKey(byte[] pubKey) {
        byte[] result= new byte[4+ pubKey.length];
        byte[] checksum= SHAHash.RIPEMD160(pubKey);
        System.arraycopy(pubKey, 0, result, 0, pubKey.length);
        System.arraycopy(checksum, 0, result, pubKey.length, 4);
        return Base58.encode(result);
    }
}
