package com.bepal.coins.keytree.coinkey;


import com.bepal.coins.crypto.Hex;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;
import com.bepal.coins.models.ByteArrayData;

import static com.bepal.coins.keytree.infrastructure.signer.Secp256k1.CURVE;

public class EthereumKey extends ACoinKey {

    public EthereumKey(ECKey ecKey) {
        super(new HDKey(ecKey), CoinConfigFactory.getConfig(CoinTag.tagETHEREUM));
    }
    public EthereumKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagETHEREUM));
    }
    public EthereumKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagETHEREUM : CoinTag.tagETHEREUMTEST)
        );
    }


    @Override
    public String address() {
        byte[] point= CURVE.getCurve().decodePoint(this.base().getPubKey()).getEncoded(false);
        byte[] pubKey= ByteArrayData.copyOfRange(point, 1, 64);
        byte[] data=  ByteArrayData.copyOfRange(SHAHash.Keccak256(pubKey), 12, 20);
        return "0x"+ Hex.toHexString(data);
    }
}
