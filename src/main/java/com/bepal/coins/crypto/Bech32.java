package com.bepal.coins.crypto;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * BTM base32 与 bch类似不同于nem
 */
public class Bech32 {
    public final static int[] gen = new int[]{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    public final static String charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static byte[] ConvertBits(byte[] data, byte fromBits, byte toBits, boolean pad) {
        if (fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8) {
            return null;
        }

        // The final bytes, each byte encoding toBits bits.
        ByteArrayOutputStream regrouped = new ByteArrayOutputStream();

        // Keep track of the next byte we create and how many bits we have
        // added to it out of the toBits goal.
        byte nextByte = 0;
        byte filledBits = 0;

        for (byte b : data) {
            // Discard unused bits.
            b = (byte) (b << (8 - fromBits));

            // How many bits remaining to extract from the input data.
            byte remFromBits = fromBits;
            while (remFromBits > 0) {
                // How many bits remaining to be added to the next byte.
                byte remToBits = (byte) (toBits - filledBits);

                // The number of bytes to next extract is the minimum of
                // remFromBits and remToBits.
                byte toExtract = remFromBits;
                if (remToBits < toExtract) {
                    toExtract = remToBits;
                }

                // Add the next bits to nextByte, shifting the already
                // added bits to the left.
                int tempb = b < 0 ? b + 256 : b;
                nextByte = (byte) ((nextByte << toExtract) | (tempb >> (8 - toExtract)));

                // Discard the bits we just extracted and get ready for
                // next iteration.
                b = (byte) (b << toExtract);
                remFromBits -= toExtract;
                filledBits += toExtract;

                // If the nextByte is completely filled, we add it to
                // our regrouped bytes and start on the next byte.
                if (filledBits == toBits) {
                    regrouped.write(nextByte);
                    filledBits = 0;
                    nextByte = 0;
                }
            }
        }

        // We pad any unfinished group if specified.
        if (pad && filledBits > 0) {
            nextByte = (byte) (nextByte << (toBits - filledBits));
            regrouped.write(nextByte);
            filledBits = 0;
            nextByte = 0;
        }

        // Any incomplete group must be <= 4 bits, and all zeroes.
        if (filledBits > 0 && (filledBits > 4 || nextByte != 0)) {
            return null;
        }

        return regrouped.toByteArray();
    }

    public static List<Integer> bech32HrpExpand(String hrp) {
        List<Integer> v = new ArrayList<>();
        for (int i = 0; i < hrp.length(); i++) {
            v.add(hrp.charAt(i) >> 5);
        }
        v.add(0);
        for (int i = 0; i < hrp.length(); i++) {
            v.add(hrp.charAt(i) & 31);
        }
        return v;
    }

    public static int bech32Polymod(List<Integer> values) {
        int chk = 1;
        for (int v : values) {
            int b = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int i = 0; i < 5; i++) {
                if (((b >> i) & 1) == 1) {
                    chk ^= gen[i];
                }
            }
        }
        return chk;
    }

    public static byte[] bech32Checksum(String hrp, byte[] data) {
        // Convert the bytes to list of integers, as this is needed for the
        // checksum calculation.
        List<Integer> integers = new ArrayList<>();
        for (byte b : data) {
            integers.add(b < 0 ? b + 256 : b);
        }
        List<Integer> values = new ArrayList<>();
        values.addAll(bech32HrpExpand(hrp));
        values.addAll(integers);
        values.add(0);
        values.add(0);
        values.add(0);
        values.add(0);
        values.add(0);
        values.add(0);
        int polymod = bech32Polymod(values) ^ 1;
        ByteArrayOutputStream res = new ByteArrayOutputStream();
        for (int i = 0; i < 6; i++) {
            res.write((polymod >> (byte) (5 * (5 - i))) & 31);
        }
        return res.toByteArray();
    }

    public static String Bech32Encode(String hrp, byte[] data) {
        // Calculate the checksum of the data and append it at the end.
        byte[] checksum = bech32Checksum(hrp, data);
        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        combined.write(data, 0, data.length);
        combined.write(checksum, 0, checksum.length);


        // The resulting bech32 string is the concatenation of the hrp, the
        // separator 1, data and checksum. Everything after the separator is
        // represented using the specified charset.
        String dataChars = toChars(combined.toByteArray());
        return hrp + "1" + dataChars;
    }

    // toChars converts the byte slice 'data' to a string where each byte in 'data'
    // encodes the index of a character in 'charset'.
    public static String toChars(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            if (b >= charset.length()) {
                return "";
            }
            result.append(charset.charAt(b));
        }
        return result.toString();
    }

    // toBytes converts each character in the string 'chars' to the value of the
    // index of the correspoding character in 'charset'.
    public static byte[] toBytes(String chars) {
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        for (int i = 0; i < chars.length(); i++) {
            int index = charset.indexOf(chars.charAt(i));
            if (index < 0) {
                return null;
            }
            decoded.write(index);
        }
        return decoded.toByteArray();
    }

    // For more details on the checksum verification, please refer to BIP 173.
    public static boolean bech32VerifyChecksum(String hrp, byte[] data) {
        List<Integer> integers = new ArrayList<>();
        integers.addAll(bech32HrpExpand(hrp));
        for (byte b : data) {
            integers.add((int) b);
        }
        return bech32Polymod(integers) == 1;
    }

    public static byte[] Bech32Decode(String bech) {
        // The maximum allowed length for a bech32 string is 90. It must also
        // be at least 8 characters, since it needs a non-empty HRP, a
        // separator, and a 6 character checksum.
        if (bech.length() < 8 || bech.length() > 90) {
            return null;
        }
        // Only	ASCII characters between 33 and 126 are allowed.
        for (int i = 0; i < bech.length(); i++) {
            if (bech.charAt(i) < 33 || bech.charAt(i) > 126) {
                return null;
            }
        }

        // The characters must be either all lowercase or all uppercase.
        String lower = bech.toLowerCase();
        String upper = bech.toUpperCase();
        if (!bech.equals(lower) && !bech.equals(upper)) {
            return null;
        }

        // We'll work with the lowercase string from now on.
        bech = lower;

        // The string is invalid if the last '1' is non-existent, it is the
        // first character of the string (no human-readable part) or one of the
        // last 6 characters of the string (since checksum cannot contain '1'),
        // or if the string is more than 90 characters in total.
        int one = bech.indexOf("1");
        if (one < 1 || one + 7 > bech.length()) {
            return null;
        }

        // The human-readable part is everything before the last '1'.
        String hrp = bech.substring(0, one);
        String data = bech.substring(one + 1);

        // Each character corresponds to the byte with value of the index in
        // 'charset'.
        byte[] decoded = toBytes(data);

        if (!bech32VerifyChecksum(hrp, decoded)) {
//            String checksum = bech.substring(bech.length() - 6);
//            String expected = toChars(bech32Checksum(hrp, Arrays.copyOfRange(decoded, 0, decoded.length - 6)));
//            if (!checksum.equals(expected)) {
//                return null;
//            }
            return null;
        }

        // We exclude the last 6 bytes, which is the checksum.
        return Arrays.copyOfRange(decoded, 0, decoded.length - 6);
    }
}
