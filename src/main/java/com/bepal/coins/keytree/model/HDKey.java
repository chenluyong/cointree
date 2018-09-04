package com.bepal.coins.keytree.model;

public class HDKey{
    public ECKey getEcKey() {
        return ecKey;
    }
    public int getDepth() {
        return depth;
    }
    public int getPath() {
        return path;
    }

    ECKey ecKey;
    int depth;
    int path;

    public HDKey(ECKey ecKey) {
        this.ecKey = ecKey;
        this.depth = 0;
        this.path = 0;
    }
    public HDKey(ECKey ecKey, int depth, int path) {
        this.ecKey = ecKey;
        this.depth = depth;
        this.path = path;
    }
}

