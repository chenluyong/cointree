package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;

public class CoinConfig {

    protected DeriveTag deriveTag;
    protected CoinTag coinTag;
    protected SeedTag seedTag;
    protected SignerTag signerTag;
    // bip44 coin index
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    protected long bip44;
    protected ICoin.NetType netType;
    protected int pubPrefix;
    protected int prvPrefix;


    //////////////////////////////// construct //////////////////////////////////

    public CoinConfig(DeriveTag deriveTag, CoinTag coinTag, SeedTag seedTag, SignerTag signerTag,
                      long bip44, ICoin.NetType netType, int pubPrefix, int prvPrefix) {
        this.deriveTag = deriveTag;
        this.coinTag = coinTag;
        this.seedTag = seedTag;
        this.signerTag = signerTag;
        this.bip44 = bip44;
        this.netType = netType;
        this.pubPrefix = pubPrefix;
        this.prvPrefix = prvPrefix;
    }
    public CoinConfig(DeriveTag deriveTag, CoinTag coinTag, SeedTag seedTag,
                      SignerTag signerTag, long bip44, ICoin.NetType main) {
        this.deriveTag = deriveTag;
        this.coinTag = coinTag;
        this.seedTag = seedTag;
        this.signerTag = signerTag;
        this.bip44 = bip44;
        this.netType = ICoin.NetType.MAIN;
        this.pubPrefix = 0x0488B21E; // xpub
        this.prvPrefix = 0x0488ADE4; // xprv
    }


    ///////////////////////////// get ////////////////////////
    public DeriveTag getDeriveTag() {
        return deriveTag;
    }

    public CoinTag getCoinTag() {
        return coinTag;
    }

    public SeedTag getSeedTag() {
        return seedTag;
    }

    public SignerTag getSignerTag() {
        return signerTag;
    }

    public long getBip44() {
        return bip44;
    }

    public ICoin.NetType getNetType() {
        return netType;
    }

    public int getPubPrefix() {
        return pubPrefix;
    }

    public int getPrvPrefix() {
        return prvPrefix;
    }
}

