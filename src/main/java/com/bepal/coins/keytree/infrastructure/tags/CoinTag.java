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


    ///////////////////////// operator ///////////////////////////

//
//    public final int compareTo(E o) {
//        Enum<?> other = (Enum<?>)o;
//        Enum<E> self = this;
//        if (self.getClass() != other.getClass() && // optimization
//                self.getDeclaringClass() != other.getDeclaringClass())
//            throw new ClassCastException();
//        return self.ordinal - other.ordinal;
//    }

    //////////////////////////////////////////////////////////////

    private final int val;
    CoinTag(int val) {
        this.val= val;
    }
}
