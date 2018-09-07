    /*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

KeyTreer
*/
package com.bepal.coins.keytree;

import com.bepal.coins.keytree.coinkey.BitcoinKey;
import com.bepal.coins.keytree.coins.*;
import com.bepal.coins.keytree.config.CoinConfig;
import com.bepal.coins.keytree.config.CoinConfigFactory;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.components.MnemonicCode;
import com.bepal.coins.keytree.infrastructure.coordinators.DeriveCoordinator;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.interfaces.IDerivator;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.tags.DeriveTag;
import com.bepal.coins.keytree.infrastructure.tags.SeedTag;
import com.bepal.coins.keytree.model.ECKey;
import com.bepal.coins.keytree.model.HDKey;
import com.bepal.coins.models.ByteArrayData;
import com.sun.xml.internal.bind.v2.runtime.Coordinator;

import java.util.Arrays;
import java.util.List;

public class KeyTreer {

    /**
     * get private key from seed
     * */
    public byte[] transSeed(List<String> codes, String passphrase) {
      return MnemonicCode.toSeed(codes, passphrase);
    }


    /**
     * 默认比特币规则
     * */
    public ICoinKey deriveHDKey(byte[] seed,CoinTag coinTag) {
        CoinConfig coinConfig = CoinConfigFactory.getConfig(coinTag);
        IDerivator derivator = DeriveCoordinator.getInstance().findDerivator(coinConfig.getDeriveTag());
        HDKey hdKey = derivator.deriveFromSeed(seed, coinConfig.getSeedTag());
        //default bitcoin key
        return new BitcoinKey(hdKey, coinConfig.getNetType());
    }



    /**
     * derive keys according to bip44
     * */
    public ICoinKey deriveBip44(byte[] seed, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveBip44(seed);
    }


    /**
     * derive second layer key
     * */
    public ICoinKey deriveSecChild(ECKey ecKey, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChild(new HDKey(ecKey));
    }

    /**
     * derive second layer range key
     * */
    public List<ICoinKey> deriveSecChildRange(ECKey ecKey, int start, int end, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildRange(new HDKey(ecKey), start, end);
    }

    /**
     * derive second layer public key by public key
     * */
    public ICoinKey deriveSecChildPub(ECKey ecKey, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildPub(new HDKey(ecKey));
    }

    /**
     * derive second layer range public key by public key
     * */
    public List<ICoinKey> deriveSecChildRangePub(ECKey ecKey, int start, int end, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildRangePub(new HDKey(ecKey), start, end);
    }

    /**
     * derive child key from seed
     * */
    public ICoinKey deriveBepalKey(byte[] seed, CoinTag coinTag) {
        ICoinKey coinKey= deriveBip44(seed, coinTag);
        return deriveSecChild(coinKey.base(), coinTag);
    }

    /**
     * derive child key range from seed
     * */
    public List<ICoinKey> deriveBepalKeyRange(byte[] seed, int start, int end, CoinTag coinTag) {
        ICoinKey coinKey= deriveBip44(seed, coinTag);
        return deriveSecChildRange(coinKey.base(), start, end, coinTag);
    }




    /////////////////////////////////////////////zformular////////////////////////////////////////////////////////////
    /**
     * pack master private key from derived ICoinKey
     * in this case, we call deriveBip44 first,
     * then using the return ICoinKey to package master private key
     *
     * @param coinKey the return of deriveBip44
     * */
    public byte[] masterPriKey(ICoinKey coinKey) {
        ECKey ecKey= coinKey.base();
        ByteArrayData data= new ByteArrayData();
        data.appendIntLE(1);
        if (ecKey.getPriKey().length== 32) {
            data.appendByte(0);
        }
        data.putBytes(ecKey.getPriKey());
        if (ecKey.getChainCode().length== 32) {
            data.appendByte(0);
        }
        data.putBytes(ecKey.getChainCode());
        return data.toBytes();
    }

    /**
     * pack master publick key from derived ICoinKey
     * in this casse, we call deriveBip44 first,
     * then using the return ICoinKey to package master public key
     *
     * @param coinKey the return of deriveBip44
     * */
    public byte[] masterPubKey(ICoinKey coinKey) {
        ECKey ecKey= coinKey.base();
        ByteArrayData data= new ByteArrayData();
        data.appendIntLE(2);
        if (ecKey.getPubKey().length== 32) {
            data.appendByte(0);
        }
        data.putBytes(ecKey.getPubKey());
        if (ecKey.getChainCode().length== 32) {
            data.appendByte(0);
        }
        data.putBytes(ecKey.getChainCode());
        return data.toBytes();
    }

    /**
     * get the root private key for SDK
     *
     * @param masterPriKey the return of masterPriKey
     * */
    public byte[] sdkPriKey(byte[] masterPriKey) {
        if (masterPriKey.length== 4+ 33+ 33) return masterPriKey;

        if (masterPriKey.length== 4+ 32+ 32) {
            ByteArrayData data= new ByteArrayData();
            data.appendIntLE(1);
            data.appendByte(0);
            data.putBytes(masterPriKey, 4, 32);
            data.appendByte(0);
            data.putBytes(masterPriKey, 4+ 32, 32);
            return data.toBytes();
        }

        if (masterPriKey.length== 4+ 32+ 33) {
            ByteArrayData data= new ByteArrayData();
            data.appendIntLE(1);
            data.appendByte(0);
            data.putBytes(masterPriKey, 4, 32);
            data.putBytes(masterPriKey, 4+ 32, 33);
            return data.toBytes();
        }

        int start= 4+ 1+ 4+ 4;
        int len= start+ 32+ 33;
        if (masterPriKey.length> len) {
            masterPriKey= Arrays.copyOfRange(masterPriKey, masterPriKey.length- len, masterPriKey.length);
        }
        ByteArrayData data= new ByteArrayData();
        data.appendIntLE(1);
        data.putBytes(masterPriKey, start+ 32, 33);
        data.appendIntLE(0);
        data.putBytes(masterPriKey, start, 32);
        return data.toBytes();
    }

    /**
     * get the root public key for SDK
     *
     * @param masterPubKey the return of masterPubKey
     * */
    public byte[] sdkPubKey(byte[] masterPubKey) {
        if (masterPubKey.length== 4+ 33+ 33) return masterPubKey;

        if (masterPubKey.length== 4+ 32+ 32) {
            ByteArrayData data= new ByteArrayData();
            data.appendIntLE(2);
            data.appendByte(0);
            data.putBytes(masterPubKey, 4, 32);
            data.appendByte(0);
            data.putBytes(masterPubKey, 4+ 32, 32);
            return data.toBytes();
        }

        if (masterPubKey.length== 4+ 32+ 33) {
            ByteArrayData data= new ByteArrayData();
            data.appendIntLE(2);
            data.appendByte(0);
            data.putBytes(masterPubKey, 4, 32);
            data.putBytes(masterPubKey, 4+ 32, 32);
            return data.toBytes();
        }

        int start= 4+ 1+ 4+ 4;
        int len= start+ 32+ 33;
        if (masterPubKey.length> len) {
            masterPubKey= Arrays.copyOfRange(masterPubKey, masterPubKey.length- len, masterPubKey.length);
        }
        ByteArrayData data= new ByteArrayData();
        data.appendIntLE(2);
        data.putBytes(masterPubKey, start+ 32, 33);
        data.appendByte(0);
        data.putBytes(masterPubKey, start, 32);
        return data.toBytes();
    }

    /**
     * to get the second layers of child keys
     *
     * @param sdkPriKey the return of sdkPriKey
     * */
    public ICoinKey deriveSDKSecChild(byte[] sdkPriKey, CoinTag coinTag) {

        ECKey ecKey= new ECKey(ByteArrayData.copyOfRange(sdkPriKey, 0+ 4, 33),
                null,ByteArrayData.copyOfRange(sdkPriKey, 33+ 4, 33),
                DeriveCoordinator.findDerivator(CoinConfigFactory.getConfig(coinTag).getDeriveTag()));
//        ecKey.setPriKey(ByteArrayData.copyOfRange(sdkPriKey, 0+ 4, 33));
//        ecKey.setChainCode(ByteArrayData.copyOfRange(sdkPriKey, 33+ 4, 33));

        return deriveSecChild(ecKey, coinTag);
    }

    /**
     * to get the second layers of child public key
     *
     * @param sdkPubKey the return of sdkPubKey
     * */
    public ICoinKey deriveSDKSecChildPub(byte[] sdkPubKey, CoinTag coinTag) {
        ECKey ecKey= new ECKey(null,ByteArrayData.copyOfRange(sdkPubKey, 0+ 4, 33),
                ByteArrayData.copyOfRange(sdkPubKey, 33+ 4, 33),
                DeriveCoordinator.findDerivator(CoinConfigFactory.getConfig(coinTag).getDeriveTag()));
        return deriveSecChildPub(ecKey, coinTag);
    }

    /**
     * using the CoinTag the specific coiner
     * */
    private ICoiner findCoiner(CoinTag coinTag) {
        final ICoin.NetType testNet= ICoin.NetType.TEST;

        switch (coinTag) {
            // main net
            case tagETHEREUM:
            case tagBITCOIN:
            case tagEOS:
            case tagGXCHAIN:
            case tagSELFSELL:
            case tagAChain:
            case tagELASTOS:
            // test net
            case tagBITCOINTEST:
            case tagETHEREUMTEST:
            case tagEOSTEST:
            case tagGXCHAINTEST:
            case tagSELFSELLTEST:
            case tagACHAINTEST:
            case tagELASTOSTEST:
                return new ACoiner(CoinConfigFactory.getConfig(coinTag));

            case tagBYTOM:
            case tagBYTOMTEST:
            case tagBYTOMSOLO:{
                return new Bytomer(CoinConfigFactory.getConfig(coinTag));
            }
        }

        return null;
    }
}
