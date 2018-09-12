package com.bepal.coins.keytree.config;

import com.bepal.coins.keytree.coins.Bytomer;
import com.bepal.coins.keytree.infrastructure.abstraction.ACoiner;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoiner;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;

public class CoinerFactory {

    /**
     * using the CoinTag the specific coiner
     * */
    public static ICoiner get(CoinTag coinTag) {
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
