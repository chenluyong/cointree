package com.bepal.coins.keytree.coinkey;

import com.bepal.coins.crypto.Bech32;
import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;

import java.io.ByteArrayOutputStream;

public class BytomKey extends ACoinKey {

    private static final String SEGWITMAIN= "bm";
    private static final String SEGWITTEST= "tm";
    private static final String SEGWITSOLO= "sm";



    public BytomKey(ECKey ecKey) {
        super(new HDKey(ecKey),CoinConfigFactory.getConfig(CoinTag.tagBYTOM));
    }

    public BytomKey(HDKey hdKey) {
        super(hdKey,CoinConfigFactory.getConfig(CoinTag.tagBYTOM));
    }

    public BytomKey(HDKey hdKey, NetType netType) {
        super(hdKey,CoinConfigFactory.getConfig(
                NetType.MAIN == netType ? CoinTag.tagBYTOM : (
                NetType.TEST == netType ? CoinTag.tagBYTOMTEST : CoinTag.tagBYTOMSOLO
                )
        ));
    }

    @Override
    public String address() {
        byte[] data = SHAHash.RIPEMD160(this.base().getPubKey());
        byte[] bData = Bech32.ConvertBits(data, (byte) 8, (byte) 5, true);
        ByteArrayOutputStream stream= new ByteArrayOutputStream();
        stream.write(0);
        stream.write(bData, 0, bData.length);

        String segwit= SEGWITMAIN;
        if (this.config.getNetType() == NetType.TEST) {
            segwit= SEGWITTEST;
        } else if (this.config.getNetType() == NetType.SOLO) {
            segwit= SEGWITSOLO;
        }


        return Bech32.Bech32Encode(segwit, stream.toByteArray());
    }

}
