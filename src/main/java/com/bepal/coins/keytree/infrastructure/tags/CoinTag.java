/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

CoinTag
*/
package com.bepal.coins.keytree.infrastructure.tags;

import com.bepal.coins.keytree.infrastructure.interfaces.ICoin;

public enum CoinTag {
    tagBITCOIN(0),
    tagETHEREUM(1),
    tagBYTOM(2),
    tagEOS(3),
    tagGXCHAIN(4),
    tagSELFSELL(5),
    tagAChain(6),
    tagELASTOS(7),


    tagTESTBEGIN(999),
    tagBITCOINTEST(1000),
    tagETHEREUMTEST(1001),
    tagBYTOMTEST(1002),
    tagEOSTEST(1003),
    tagGXCHAINTEST(1004),
    tagSELFSELLTEST(1005),
    tagACHAINTEST(1006),
    tagELASTOSTEST(1007),
    tagTESTEND(1008),


    tagBYTOMSOLO(10002),
    ;

    public ICoin.NetType getNetType() {
        ICoin.NetType ret = ICoin.NetType.MAIN;
        if (this.compareTo(CoinTag.tagTESTBEGIN) > 0
                && this.compareTo(CoinTag.tagTESTEND) < 0) {
            ret = ICoin.NetType.TEST;
        }
        else if (this.compareTo(CoinTag.tagTESTEND) > 0) {
            ret = ICoin.NetType.SOLO;
        }
        return ret;
    }

    ///////////////////////// operator ///////////////////////////

    // https://gitlab.eshanren.com/chenluyong/bepal/blob/master/doc/protocol/table.md
    public int getPubPrefix() {
        // bip32 header
        int pubPrefix = 0x0488B21E; // xpub
        if (getNetType() != ICoin.NetType.MAIN) {
            pubPrefix = 0x043587CF; // tpub
        }
        return pubPrefix;
    }
    public int getPrvPrefix() {
        // bip32 header
        int prvPrefix = 0x0488ADE4; // xprv
        if (getNetType() != ICoin.NetType.MAIN) {
            prvPrefix = 0x04358394; // tprv
        }
        return prvPrefix;
    }

    //////////////////////////////////////////////////////////////

    private final int val;
    CoinTag(int val) {
        this.val= val;
    }
}
