package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Base58;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.components.GrapheneSerializer;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.ECSign;
import com.bepal.coins.keytree.model.HDKey;

public class AChainKey extends ACoinKey {

    public AChainKey(ECKey ecKey) {
        super(new HDKey(ecKey),CoinConfigFactory.getConfig(CoinTag.tagAChain));
    }

    public AChainKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagAChain));
    }
    public AChainKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagAChain : CoinTag.tagACHAINTEST
        ));
    }

    @Override
    public String address() {
        byte[] pubKey= this.base().getPubKey();
        byte[] addr= SHAHash.sha512hash160(pubKey);
        byte[] checksum= SHAHash.RIPEMD160(addr);

        byte[] result= new byte[24];
        System.arraycopy(addr, 0, result, 0, addr.length);
        System.arraycopy(checksum, 0, result, addr.length, 4);
        return "ACT" + Base58.encode(result);
    }

    @Override
    public String publicKey() {
        return "ACT"+ GrapheneSerializer.serializePubKey(this.base().getPubKey());
    }

    @Override
    public String privateKey() {
        return GrapheneSerializer.wifPriKey(this.base().getPriKey());
    }
}
