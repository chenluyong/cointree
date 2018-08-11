/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.31               |
|                                            |
╰============================================╯

SignerCoordinator
*/
package com.bepal.coins.keytree.infrastructure.coordinators;

import com.bepal.coins.keytree.infrastructure.interfaces.ISigner;
import com.bepal.coins.keytree.infrastructure.signer.Secp256r1;
import com.bepal.coins.keytree.infrastructure.tags.SignerTag;
import com.bepal.coins.keytree.infrastructure.signer.ED25519;
import com.bepal.coins.keytree.infrastructure.signer.Secp256k1;
import com.bepal.coins.keytree.infrastructure.signer.Secp256k1Nonce;

public class SignerCoordinator {
    private static SignerCoordinator instance;

    private SignerCoordinator() {}


    public static SignerCoordinator getInstance() {
        if (instance== null) {
            instance= new SignerCoordinator();
        }
        return instance;
    }

    public ISigner findSigner(SignerTag signerTag) {
        switch (signerTag) {
            case tagSECP256K1: {
                return new Secp256k1();
            }
            case tagSECP256K1NONCE: {
                return new Secp256k1Nonce();
            }
            case tagED25519: {
                return new ED25519();
            }
            case tagSECP256R1:{
                return new Secp256r1();
            }
        }

        return null;
    }
}
