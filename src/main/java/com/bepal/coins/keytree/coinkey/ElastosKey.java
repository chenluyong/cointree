package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

public class ElastosKey extends ACoinKey {


    public ElastosKey(ECKey ecKey) {
        super(new HDKey(ecKey),CoinConfigFactory.getConfig(CoinTag.tagELASTOS));
    }
    public ElastosKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagELASTOS));
    }
    public ElastosKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagELASTOS : CoinTag.tagELASTOSTEST)
        );
    }


    @Override
    public String address() {
        byte[] program = createSingleSignatureRedeemScript(this.base().getPubKey());
        byte[] programHash = toCodeHash(program,1);
        return toAddress(programHash);
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
