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
    public ICoinKey deriveHDKey(byte[] seed) {

        IDerivator derivator = DeriveCoordinator.getInstance().findDerivator(DeriveTag.tagBITCOIN);
        ECKey ecKey= derivator.deriveFromSeed(seed, SeedTag.tagBITCOIN);
        ecKey.setPubKey(derivator.derivePubKey(ecKey.getPriKey()));

        // default bitcoin key
        return new BitcoinKey(ecKey,0,0,ICoin.NetType.MAIN);
    }


    /////////////////////////////////////////////zformular////////////////////////////////////////////////////////////
    /**
     * derive keys according to bip44
     * */
    public HDKey deriveBip44(byte[] seed, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveBip44(seed);
    }


    /**
     * derive second layer key
     * */
    public HDKey deriveSecChild(ECKey ecKey, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChild(new HDKey(ecKey));
    }

    /**
     * derive second layer range key
     * */
    public List<HDKey> deriveSecChildRange(ECKey ecKey, int start, int end, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildRange(new HDKey(ecKey), start, end);
    }

    /**
     * derive second layer public key by public key
     * */
    public HDKey deriveSecChildPub(ECKey ecKey, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildPub(new HDKey(ecKey));
    }

    /**
     * derive second layer range public key by public key
     * */
    public List<HDKey> deriveSecChildRangePub(ECKey ecKey, int start, int end, CoinTag coinTag) {
        ICoiner coiner= findCoiner(coinTag);
        if (coiner== null) return null;

        return coiner.deriveSecChildRangePub(new HDKey(ecKey), start, end);
    }

    /**
     * derive child key from seed
     * */
    public HDKey deriveBepalKey(byte[] seed, CoinTag coinTag) {
        HDKey coinKey= deriveBip44(seed, coinTag);
        return deriveSecChild(coinKey.getEcKey(), coinTag);
    }

    /**
     * derive child key range from seed
     * */
    public List<HDKey> deriveBepalKeyRange(byte[] seed, int start, int end, CoinTag coinTag) {
        HDKey coinKey= deriveBip44(seed, coinTag);
        return deriveSecChildRange(coinKey.getEcKey(), start, end, coinTag);
    }

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
    public HDKey deriveSDKSecChild(byte[] sdkPriKey, CoinTag coinTag) {
        ECKey ecKey= new ECKey();
        ecKey.setPriKey(ByteArrayData.copyOfRange(sdkPriKey, 0+ 4, 33));
        ecKey.setChainCode(ByteArrayData.copyOfRange(sdkPriKey, 33+ 4, 33));

        return deriveSecChild(ecKey, coinTag);
    }

    /**
     * to get the second layers of child public key
     *
     * @param sdkPubKey the return of sdkPubKey
     * */
    public HDKey deriveSDKSecChildPub(byte[] sdkPubKey, CoinTag coinTag) {
        ECKey ecKey= new ECKey();
        ecKey.setPubKey(ByteArrayData.copyOfRange(sdkPubKey, 0+ 4, 33));
        ecKey.setChainCode(ByteArrayData.copyOfRange(sdkPubKey, 33+ 4, 33));

        return deriveSecChildPub(ecKey, coinTag);
    }

    /**
     * using the CoinTag the specific coiner
     * */
    private ICoiner findCoiner(CoinTag coinTag) {
        final ICoin.NetType testNet= ICoin.NetType.TEST;

        switch (coinTag) {
            // main net
            case tagBITCOIN: {
                return new Bitcoiner();
            }
//            case tagETHEREUM: {
//                return new Ethereumer();
//            }
//            case tagBYTOM: {
//                return new Bytomer();
//            }
//            case tagEOS: {
//                return new Eoser();
//            }
//            case tagGXCHAIN: {
//                return new GXChainer();
//            }
//            case tagSELFSELL: {
//                return new Selfseller();
//            }
//            case tagAChain: {
//                return new AChainer();
//            }
//            case tagELASTOS: {
//                return new Elastoser();
//            }


            // test net
            case tagBITCOINTEST: {
                return new Bitcoiner(testNet);
            }
//            case tagETHEREUMTEST: {
//                return new Ethereumer(testNet);
//            }
//            case tagBYTOMTEST: {
//                return new Bytomer(testNet);
//            }
//            case tagEOSTEST: {
//                return new Eoser(testNet);
//            }
//            case tagGXCHAINTEST: {
//                return new GXChainer(testNet);
//            }
//            case tagSELFSELLTEST: {
//                return new Selfseller(testNet);
//            }
//            case tagACHAINTEST: {
//                return new AChainer(testNet);
//            }
//            case tagELASTOSTEST:{
//                return new Elastoser(testNet);
//            }
//
//
//            // other net
//            case tagBYTOMSOLO: {
//                return new Bytomer(ICoin.NetType.SOLO);
//            }
        }

        return null;
    }
}
