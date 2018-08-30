package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.Hex;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;

import java.math.BigInteger;

public class ElastosKey extends ACoinKey {

    public ElastosKey(ECKey ecKey) {
        super(ecKey,0,0);
    }
    public ElastosKey(ECKey _ecKey, int _depth, int _path) {
        super(_ecKey,_depth,_path);
    }

    @Override
    public ECKey base() {
        return this.ecKey;
    }

    @Override
    public String address() {
        byte[] program = createSingleSignatureRedeemScript(this.ecKey.getPubKey());
        byte[] programHash = toCodeHash(program,1);
        return toAddress(programHash);
    }

    @Override
    public String publicKey() {
        return Hex.toHexString(this.ecKey.getPubKey());
    }

    @Override
    public String privateKey() {
        return Hex.toHexString(this.ecKey.getPriKey());
    }

    @Override
    public ECSign sign(byte[] hash) {
        return null;
    }

    @Override
    public boolean verify(byte[] hash, ECSign ecSign) {
        return false;
    }


    /// ----------------------------
    private static byte[] createSingleSignatureRedeemScript(byte[] pubkey) {
        byte[] script = new byte[35];
        script[0] = 33;
        System.arraycopy(pubkey,0,script,1,33);
        script[34] = (byte)0xAC;

        return script;
    }

    /**
     * 公钥/脚本合约 到 公钥/脚本合约 哈希 转换 单向
     * @param code
     * @param signType
     * @return
     */
    private static byte[] toCodeHash(byte[] code, int signType) {

        byte[] f = SHAHash.sha256hash160(code);
        byte[] g = new byte[f.length+1];

        if (signType == 1) {
            g[0] = 33;
            System.arraycopy(f,0,g,1,f.length);
        } else if (signType == 2) {
            g[0] = 18;
        } else{
            return null;
        }
        System.arraycopy(f,0,g,1,f.length);
        return g;

    }

    /**
     * 公钥/脚本 哈希 到地址转换 可逆（ToScriptHash)
     * @param programHash
     * @return
     */
    private static String toAddress(byte[] programHash){
        byte[] f = SHAHash.hash2256Twice(programHash);
        byte[] g = new byte[programHash.length+4];
        System.arraycopy(programHash,0,g,0,programHash.length);
        System.arraycopy(f,0,g,programHash.length,4);

        //BigInteger bi = new BigInteger(g);

        return Base58.encode(g);
    }
}

