package com.bepal.coins.keytree.infrastructure.interfaces;

public interface ICoin {

    /**
     * net type: main or test
     * */
    public enum NetType {
        MAIN(0),
        TEST(1),
        SOLO(2);


        private final int val;
        NetType(int val) {
            this.val= val;
        }
    }

//    NetType netType;
}
