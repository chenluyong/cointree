/*
>>>------ Copyright (c) 2018 zformular ------>
|                                            |
|            Author: zformular               |
|        E-mail: zformular@163.com           |
|             Date: 2018.07.30               |
|                                            |
╰============================================╯

KeyTreerTest
*/

package com.bepal.coins.keytree;

import com.bepal.coins.crypto.SHAHash;
import com.bepal.coins.keytree.infrastructure.interfaces.ICoinKey;
import com.bepal.coins.keytree.infrastructure.tags.CoinTag;
import com.bepal.coins.keytree.model.ECSign;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class KeyTreerTest {

    @Test
    public void transSeed() {
        String codes = "spider oven phrase short also flight slender sponsor control code tube pave";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");
        String seedStr = "";
        for (byte se : seed) {
            seedStr += se;
        }
        String expected = "118-146048-17-1262451996-4415104-97-123-72-62902-101062961-45-72-62-119-123211247228686823-20-12123-67-892113821412096120-24109631-62-60117-1109-40-12286-1001161226183";
        Assert.assertEquals("rannsSeed failed", expected, seedStr);
    }

    @Test
    public void deriveBip44() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        String address = "";
        String expect = "1FFiZJj3th8zRktVZi3Gyn7wARmQ3p8S36";

        ICoinKey coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBITCOIN);

        coinKey = keyTreer.deriveSecChild(coinKey.base(), CoinTag.tagBITCOIN);
        address = coinKey.address();
        Assert.assertEquals("deriveBip44 failed address dismatch", expect, address);

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBITCOIN);
        byte[] masterPriKey = keyTreer.masterPriKey(coinKey);
        byte[] sdkPriKey = keyTreer.sdkPriKey(masterPriKey);

        coinKey = keyTreer.deriveSDKSecChild(sdkPriKey, CoinTag.tagBITCOIN);
        address = coinKey.address();
        Assert.assertEquals("deriveBip44 failed address dismatch", expect, address);
    }

    @Test
    public void deriveSecChildPub() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        String address = "";
        String expect = "1FFiZJj3th8zRktVZi3Gyn7wARmQ3p8S36";

        ICoinKey coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBITCOIN);
        byte[] masterPubKey = keyTreer.masterPubKey(coinKey);
        byte[] sdkPubKey = keyTreer.sdkPubKey(masterPubKey);
        coinKey = keyTreer.deriveSDKSecChildPub(sdkPubKey, CoinTag.tagBITCOIN);
        address = coinKey.address();
        Assert.assertEquals("deriveSecChildPub failed address dismatch", expect, address);

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBITCOIN);
        coinKey = keyTreer.deriveSecChildPub(coinKey.base(), CoinTag.tagBITCOIN);
        address = coinKey.address();
        Assert.assertEquals("deriveSecChildPub failed address dismatch", expect, address);
    }

    @Test
    public void deriveSecChildRangePub() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        String address = "";
        String[] expects = new String[]{"1FFiZJj3th8zRktVZi3Gyn7wARmQ3p8S36", "1PyBbSjHyLYrSZ3JXhe3m6Xzfp5Ywzt954"};

        ICoinKey coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBITCOIN);
        List<ICoinKey> coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagBITCOIN);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveSecChildRangePub bitcoin faield,  address dismatch", expects[i], address);
        }
        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagETHEREUM);
        expects = new String[]{"0x063b07ee7b38291c1c0e36686e2e1e5e6b3f3dde", "0x3ba33bdc008b40bcb229751907c439c6d3819b4f"};
        coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagETHEREUM);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange ethereum faield,  address dismatch", expects[i], address);
        }

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagBYTOM);
        expects = new String[]{"bm1qdef50r0zz5jr8r3juvr93htu2uq0hsahnsrpmq", "bm1qlh8ujxq86gkw4cm928ktt56j6rzxa2c86muaqf"};
        coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagBYTOM);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange bytom faield,  address dismatch", expects[i], address);
        }

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagEOS);
        expects = new String[]{"EOS6KZheUhLuVkzQheaJG5Bxn3S1VPzCzPJ9DjRisrZkKkC2mwWXT", "EOS5bgoXZVUdjpnoZaTi9eNLtZkYqnW3GrJg5TDuxHmpQa7MiRZNx"};
        coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagEOS);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange eos faield,  address dismatch", expects[i], address);
        }

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagGXCHAIN);
        expects = new String[]{"GXC57jfmhcAsCPs7LSKrowj7CymSJdkG8czStampQZYyau36VH6Ji", "GXC7FfT1du67MNVZJxSGCe4zE7UqsoGJ97QRfxPHAkxBgdVHvyEdi"};
        coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagGXCHAIN);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange gxchain faield,  address dismatch", expects[i], address);
        }

        coinKey = keyTreer.deriveBip44(seed, CoinTag.tagELASTOS);
        expects = new String[]{"ENu66Di2wpwimBUKcHiL5fn1f1HDVPn3uu", "EJUGryNES35U3LUniX75MBqVaZni5st6gu"};
        coinKeys = keyTreer.deriveSecChildRangePub(coinKey.base(), 0, 1, CoinTag.tagELASTOS);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange elastos faield,  address dismatch", expects[i], address);
        }

    }

    @Test
    public void deriveBepalKey() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        String address = "", pubkey = "";
        String expect = "1FFiZJj3th8zRktVZi3Gyn7wARmQ3p8S36";
        ICoinKey coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBITCOIN);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey bitcoin failed, address dismatch", expect, address);

        expect = "0x063b07ee7b38291c1c0e36686e2e1e5e6b3f3dde";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagETHEREUM);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey ethereum failed, address dismatch", expect, address);

        expect = "bm1qdef50r0zz5jr8r3juvr93htu2uq0hsahnsrpmq";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBYTOM);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey bytom failed, address dismatch", expect, address);

        expect = "EOS6KZheUhLuVkzQheaJG5Bxn3S1VPzCzPJ9DjRisrZkKkC2mwWXT";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagEOS);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey eos failed, address dismatch", expect, address);

        expect = "GXC57jfmhcAsCPs7LSKrowj7CymSJdkG8czStampQZYyau36VH6Ji";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagGXCHAIN);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey gxchain failed, address dismatch", expect, address);

        expect = "SSC6km11fQXws75EamGd3JbU4kaKnSUdUXVpidHs418q9cNnYd7e8";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagSELFSELL);
        pubkey = coinKey.publicKey();
        Assert.assertEquals("deriveBepalKey selfsell failed, address dismatch", expect, pubkey);

        expect = "SSCPJPiW9WHgVPgWXdtdAiSAHDjPWKDEY7Dx";
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey selfsell failed, address dismatch", expect, address);


        expect = "mvD7iGnPrJ7KjTMVNdKCbcvSGGD1Ew4urE";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBITCOINTEST);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey bitcoin test net failed, address dismatch", expect, address);

        expect = "0xc9b3d56861111a7a05687b2ef446f32750dd9721";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagETHEREUMTEST);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey ethereum test net failed, address dismatch", expect, address);

        expect = "tm1qf6efxyu8e7z65u273ytnw767sypq7dmv3cfu05";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBYTOMTEST);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey bytom test failed, address dismatch", expect, address);

        expect = "EOS686AHcgGFTrzYfmSPq23xuHgDqHELzoN5Dm2qvCEoR38U4Mge6";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagEOSTEST);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey eos test failed, address dismatch", expect, address);

        expect = "ACTCLp3vzhFNwSDN9xjQgVi1WEpr59iHa4TQ";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagAChain);
        address = coinKey.address();
        Assert.assertEquals("deriveBepalKey eos test failed, address dismatch", expect, address);


        expect = "ENu66Di2wpwimBUKcHiL5fn1f1HDVPn3uu";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagELASTOS);
        address = coinKey.address();
        System.out.println(coinKey.privateKey());
        Assert.assertEquals("deriveBepalKey eos test failed, address dismatch", expect, address);


    }

    @Test
    public void deriveBepalKeyRange() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        String address = "", pubKey = "";
        String[] expects = new String[]{"1FFiZJj3th8zRktVZi3Gyn7wARmQ3p8S36", "1PyBbSjHyLYrSZ3JXhe3m6Xzfp5Ywzt954"};
        List<ICoinKey> coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagBITCOIN);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange bitcoin faield,  address dismatch", expects[i], address);
        }

        expects = new String[]{"0x063b07ee7b38291c1c0e36686e2e1e5e6b3f3dde", "0x3ba33bdc008b40bcb229751907c439c6d3819b4f"};
        coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagETHEREUM);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange ethereum faield,  address dismatch", expects[i], address);
        }

        expects = new String[]{"bm1qdef50r0zz5jr8r3juvr93htu2uq0hsahnsrpmq", "bm1qlh8ujxq86gkw4cm928ktt56j6rzxa2c86muaqf"};
        coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagBYTOM);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange bytom faield,  address dismatch", expects[i], address);
        }

        expects = new String[]{"EOS6KZheUhLuVkzQheaJG5Bxn3S1VPzCzPJ9DjRisrZkKkC2mwWXT", "EOS5bgoXZVUdjpnoZaTi9eNLtZkYqnW3GrJg5TDuxHmpQa7MiRZNx"};
        coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagEOS);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange eos faield,  address dismatch", expects[i], address);
        }

        expects = new String[]{"GXC57jfmhcAsCPs7LSKrowj7CymSJdkG8czStampQZYyau36VH6Ji", "GXC7FfT1du67MNVZJxSGCe4zE7UqsoGJ97QRfxPHAkxBgdVHvyEdi"};
        coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagGXCHAIN);
        for (int i = 0; i < 2; i++) {
            address = coinKeys.get(i).address();
            Assert.assertEquals("deriveBepalKeyRange gxchain faield,  address dismatch", expects[i], address);
        }

        expects = new String[]{"SSC6km11fQXws75EamGd3JbU4kaKnSUdUXVpidHs418q9cNnYd7e8", "SSC59fMtdggcUa7bt3BXAopx9uFoiJFZpX4LFQjFeV6WtM2EoMCgq"};
        coinKeys = keyTreer.deriveBepalKeyRange(seed, 0, 1, CoinTag.tagSELFSELL);
        for (int i = 0; i < 2; i++) {
            pubKey = coinKeys.get(i).publicKey();
            Assert.assertEquals("deriveBepalKeyRange selfsell faield,  address dismatch", expects[i], pubKey);
        }
    }

    @Test
    public void sign() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");

        byte[] msg = SHAHash.MD5("helloworldlrowolleh".getBytes());

        String sign = "";
        String expect = "00b6e117c9f0c5d6afd8fba7af1b0a78f1ab7e7c7ed7ef91c78c259253cf46384266616a9e1277dd3f9259556c26baa1b9ff4f132e23227aade372bfc526f1d028";
        ICoinKey coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBITCOIN);
        ECSign ecSign = coinKey.sign(msg);
        sign = ecSign.toHex();
        Assert.assertEquals("sign bitcoin failed, sign dismatch", expect, sign);

        expect = "00e5cb35bf2a1633ef5ae0e103faffa49e07792ff6c4ee545031d08d4da4bdd30a3277840af4472277e7070a240addd1d9ada5594d8aca43530017198b98ad32f1";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagETHEREUM);
        ecSign = coinKey.sign(msg);
        sign = ecSign.toHex();
        Assert.assertEquals("sign ethereum failed, sign dismatch", expect, sign);

        expect = "bfe5377126c8fc46c85eaed4e3546c289706d3611887286e57d1190ccab7b0ffe16fcdb971ce6c5062f55271e6dbc19306d6d5e8d0c709909a9511eb0507b802";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBYTOM);
        ecSign = coinKey.sign(msg);
        sign = ecSign.toHex();
        Assert.assertEquals("sign bytom failed, sign dismatch", expect, sign);

        msg = SHAHash.Sha2256("helloworldlrowolleh".getBytes());
        expect = "010749784950eb7c2678757da0192afdb82e25667650028ee3138ebe0a94c96eb97a931055a7ed0aa103dc12251b5198765d39bdf400a5c116a4b0b8239ac72208";
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagEOS);
        ecSign = coinKey.sign(msg);
        sign = ecSign.toHex();
        Assert.assertEquals("sign eos failed, sign dismatch", expect, sign);
    }

    @Test
    public void signVerify() {
        String codes = "beyond honey crisp weird type coast pair endless idle glad famous visa";
        String[] codeAry = codes.split(" ");
        List<String> list = new ArrayList<>();
        for (String code : codeAry) {
            list.add(code);
        }

        KeyTreer keyTreer = new KeyTreer();
        byte[] seed = keyTreer.transSeed(list, "");
        byte[] msg = SHAHash.MD5("helloworldlrowolleh".getBytes());

        boolean verify;
        boolean expect = true;
        ICoinKey coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBITCOIN);
        ECSign ecSign = coinKey.sign(msg);
        verify = coinKey.verify(msg, ecSign);
        Assert.assertEquals("signVerify bitcoin failed, sign dismatch", expect, verify);

        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagETHEREUM);
        ecSign = coinKey.sign(msg);
        verify = coinKey.verify(msg, ecSign);
        Assert.assertEquals("signVerify ethereum failed, sign dismatch", expect, verify);

        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagBYTOM);
        ecSign = coinKey.sign(msg);
        verify = coinKey.verify(msg, ecSign);
        Assert.assertEquals("signVerify bytom failed, sign dismatch", expect, verify);

        msg = SHAHash.Sha2256("helloworldlrowolleh".getBytes());
        coinKey = keyTreer.deriveBepalKey(seed, CoinTag.tagEOS);
        ecSign = coinKey.sign(msg);
        verify = coinKey.verify(msg, ecSign);
        Assert.assertEquals("signVerify eos failed, sign dismatch", expect, verify);
    }

    @Test
    public void batchDeriveBepalKey() {
        String[] files = new String[]{
                "btc", "eth", "btm", "eos", "gxc", "ssc"
        };
        CoinTag[] coinTags = new CoinTag[]{
                CoinTag.tagBITCOIN, CoinTag.tagETHEREUM, CoinTag.tagBYTOM, CoinTag.tagEOS, CoinTag.tagGXCHAIN, CoinTag.tagSELFSELL
        };

        BufferedReader reader = null;
        String code, addr, valid;

        String address;
        ICoinKey coinKey;
        List<String> list = new ArrayList<>();
        try {
            KeyTreer keyTreer = new KeyTreer();
            for (int i = 0; i < files.length; i++) {
                File file = new File(this.getClass().getClassLoader().getResource(files[i] + ".txt").getPath());
                reader = new BufferedReader(new FileReader(file));
                do {
                    code = reader.readLine();
                    if (code == null || code.isEmpty()) break;
                    addr = reader.readLine();
                    if (addr == null || addr.isEmpty()) break;
                    valid = reader.readLine();
                    if (valid == null || valid.isEmpty()) break;
                    reader.readLine();
                    reader.readLine();

                    String[] codeAry = code.split(" ");
                    list.clear();
                    for (String cd : codeAry) {
                        list.add(cd);
                    }
                    byte[] seed = keyTreer.transSeed(list, "");
                    coinKey = keyTreer.deriveBepalKey(seed, coinTags[i]);

                    address = coinKey.address();
                    System.out.println(files[i] + ": " + address);
                    Assert.assertEquals("batchDeriveBepalKey " + files[i] + " failed, address dismatch,\nexpect: "
                            + code + "\ngot: " + addr, addr, address);
                } while (true);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void batchDerivePub() {
        String[] files = new String[]{"btcpub", "ethpub", "btmpub", "eospub"};
        CoinTag[] coinTags = new CoinTag[]{CoinTag.tagBITCOIN, CoinTag.tagETHEREUM, CoinTag.tagBYTOM, CoinTag.tagEOS};

        BufferedReader reader = null;
        String code, addr, valid;

        String address;
        ICoinKey coinKey;
        List<String> list = new ArrayList<>();
        try {
            KeyTreer keyTreer = new KeyTreer();
            for (int i = 0; i < files.length; i++) {
                File file = new File(this.getClass().getClassLoader().getResource(files[i] + ".txt").getPath());
                reader = new BufferedReader(new FileReader(file));
                do {
                    code = reader.readLine();
                    if (code == null || code.isEmpty()) break;
                    addr = reader.readLine();
                    if (addr == null || addr.isEmpty()) break;
                    valid = reader.readLine();
                    if (valid == null || valid.isEmpty()) break;
                    reader.readLine();
                    reader.readLine();

                    String[] codeAry = code.split(" ");
                    list.clear();
                    for (String cd : codeAry) {
                        list.add(cd);
                    }
                    byte[] seed = keyTreer.transSeed(list, "");
                    coinKey = keyTreer.deriveBip44(seed, coinTags[i]);
                    coinKey = keyTreer.deriveSecChildPub(coinKey.base(), coinTags[i]);

                    address = coinKey.address();
                    System.out.println(files[i] + ": " + address);
                    Assert.assertEquals("batchDerivePub " + files[i] + " failed, address dismatch,\nexpect: "
                            + code + "\ngot: " + addr, addr, address);
                } while (true);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testMain() {
    }

}