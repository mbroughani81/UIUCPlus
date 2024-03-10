import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RegressionTest4 {

    public static boolean debug = false;

    @Test
    public void test2001() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2001");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        java.nio.ByteBuffer byteBuffer4 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest2, byteBuffer4);
        java.security.MessageDigest messageDigest6 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils7 = new org.apache.commons.codec.digest.DigestUtils(messageDigest6);
        java.io.OutputStream outputStream8 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_10 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream12 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream8, (org.apache.commons.codec.binary.BaseNCodec) base16_10, false);
        byte[] byteArray15 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str16 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray15);
        long long17 = base16_10.getEncodedLength(byteArray15);
        byte[] byteArray18 = digestUtils7.digest(byteArray15);
        java.security.MessageDigest messageDigest19 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils20 = new org.apache.commons.codec.digest.DigestUtils(messageDigest19);
        java.security.MessageDigest messageDigest21 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer23 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest24 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest21, byteBuffer23);
        char[] charArray26 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer23, true);
        java.lang.String str27 = digestUtils20.digestAsHex(byteBuffer23);
        byte[] byteArray28 = digestUtils7.digest(byteBuffer23);
        java.security.MessageDigest messageDigest29 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest2, byteBuffer23);
        java.lang.String str31 = org.apache.commons.codec.binary.Hex.encodeHexString(byteBuffer23, true);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer4);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[95, 64, -81, 13, 25, -127, -108, 67, 56, -44, -88, -75, -99, -26, -30, 113, 23, 21, 27, -41, 118, 105, 115, 47, 101, 11, 38, -60, 92, 74, -64, -41, 6, 12, 32, 127, -27, 36, 65, -15, -87, -50, -127, 34, -41, -17, 116, -114, -90, -124, -31, -3, -42, -50, 73, 70, -5, 101, -75, -58, -79, 57, -126, 119]");
        org.junit.Assert.assertNotNull(messageDigest6);
        org.junit.Assert.assertEquals(messageDigest6.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(outputStream8);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "\000\ufffd" + "'", str16, "\000\ufffd");
        org.junit.Assert.assertTrue("'" + long17 + "' != '" + 4L + "'", long17 == 4L);
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[118, 16, 18, -102, -37, -99, -101, 93, -121, -6, 112, 76, 20, -78, -89, -111, 104, -101, 56, 39, -120, -81, 72, -106, 82, 11, 76, 29, 47, -108, 35, -72, -58, -24, -103, 19, -66, 1, 77, -23, 89, -100, 93, 116, 115, 18, -91, -9]");
        org.junit.Assert.assertNotNull(messageDigest19);
        org.junit.Assert.assertEquals(messageDigest19.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest21);
        org.junit.Assert.assertEquals(messageDigest21.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer23);
        org.junit.Assert.assertNotNull(messageDigest24);
        org.junit.Assert.assertEquals(messageDigest24.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray26);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray26), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray26), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray26), "[]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" + "'", str27, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(messageDigest29);
        org.junit.Assert.assertEquals(messageDigest29.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "" + "'", str31, "");
    }

    @Test
    public void test2002() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2002");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        java.lang.String str2 = doubleMetaphone0.doubleMetaphone("kBAwnYFpJm7aQ");
        org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult4 = doubleMetaphone0.new DoubleMetaphoneResult(686869806);
        doubleMetaphoneResult4.appendPrimary("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        doubleMetaphoneResult4.appendPrimary('4');
        boolean boolean9 = doubleMetaphoneResult4.isComplete();
        doubleMetaphoneResult4.append("MTAwMTAwMTAxMDAxMTEwMTAxMDExMDAwMDEwMDEwMTAwMTEwMTAwMTExMDAxMDExMDExMDAxMTExMDAxMTAxMTAwMDExMDAwMDAwMDExMDAxMDExMDExMDAwMDEwMDAxMTEwMDExMDEwMDAxMDAxMTExMTAxMDAwMDAwMDExMDEwMTExMDAwMDEwMDAwMDExMTAxMTAwMTAxMTAxMTAwMTAwMTEwMDAwMTExMDExMDAxMDEwMDEwMDAwMDAxMDExMDAxMTExMDEwMDExMTExMDExMDEwMTEwMTAxMTAxMTE=", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "KPNF" + "'", str2, "KPNF");
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + false + "'", boolean9 == false);
    }

    @Test
    public void test2003() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2003");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = uRLCodec1.encode(byteArray6);
        java.lang.String str8 = uRLCodec1.getDefaultCharset();
        byte[] byteArray10 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.shaHex(byteArray10);
        byte[] byteArray12 = uRLCodec1.encode(byteArray10);
        java.lang.String str13 = uRLCodec1.getEncoding();
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "hi!" + "'", str8, "hi!");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "ca73f0c17889db16a65cc87b97ac0bcd537d3f9d" + "'", str11, "ca73f0c17889db16a65cc87b97ac0bcd537d3f9d");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[37, 48, 48, 104, 37, 48, 48, 105, 37, 48, 48, 37, 50, 49]");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "hi!" + "'", str13, "hi!");
    }

    @Test
    public void test2004() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2004");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) (byte) 100, 2);
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + 411534142 + "'", int2 == 411534142);
    }

    @Test
    public void test2005() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2005");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.lang.String str15 = quotedPrintableCodec1.getDefaultCharset();
        java.lang.String str16 = quotedPrintableCodec1.getDefaultCharset();
        java.lang.String str18 = quotedPrintableCodec1.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.nio.charset.Charset charset20 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy21 = null;
        org.apache.commons.codec.net.BCodec bCodec22 = new org.apache.commons.codec.net.BCodec(charset20, codecPolicy21);
        org.apache.commons.codec.net.QCodec qCodec23 = new org.apache.commons.codec.net.QCodec(charset20);
        java.lang.String str24 = quotedPrintableCodec1.decode("728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6", charset20);
        org.apache.commons.codec.net.QCodec qCodec25 = new org.apache.commons.codec.net.QCodec(charset20);
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str8, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str10, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "AAAAAAA" + "'", str11, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str12, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str13, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "UTF-8" + "'", str15, "UTF-8");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "UTF-8" + "'", str16, "UTF-8");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str18, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(charset20);
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6" + "'", str24, "728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6");
    }

    @Test
    public void test2006() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2006");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex("c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a", "");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "d453740fa12add9e45759e82fb0fa5d58dd7c744ea3d6c3d7b427b9c6d0d41e91205fc98b8dce61b494a7a40f776e89239cdc25a5ba4a4d572e020eb0dee5b89" + "'", str2, "d453740fa12add9e45759e82fb0fa5d58dd7c744ea3d6c3d7b427b9c6d0d41e91205fc98b8dce61b494a7a40f776e89239cdc25a5ba4a4d572e020eb0dee5b89");
    }

    @Test
    public void test2007() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2007");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray4 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        base64OutputStream1.write(byteArray4);
        base64OutputStream1.write((int) '4');
        boolean boolean8 = base64OutputStream1.isStrictDecoding();
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.md5("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray12);
        byte[] byteArray17 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str18 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray17);
        org.apache.commons.codec.binary.Base32 base32_19 = new org.apache.commons.codec.binary.Base32((int) '4', byteArray17);
        org.apache.commons.codec.CodecPolicy codecPolicy20 = base32_19.getCodecPolicy();
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32OutputStream base32OutputStream21 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, false, 1137768543, byteArray12, codecPolicy20);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain Base32 characters: [{v??)|??#O???????]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[123, 118, -12, -87, 41, 124, 1, 20, 35, -56, -84, -61, -49, 11, -8, -51]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-85, -81, -65, 26, -99, 117, -2, -64, -79, -99, -10, -51, -128, 66, -110, 44, -106, 120, -37, -119]");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "\000\ufffd" + "'", str18, "\000\ufffd");
        org.junit.Assert.assertTrue("'" + codecPolicy20 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy20.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test2008() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2008");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md5("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[123, 118, -12, -87, 41, 124, 1, 20, 35, -56, -84, -61, -49, 11, -8, -51]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-85, -81, -65, 26, -99, 117, -2, -64, -79, -99, -10, -51, -128, 66, -110, 44, -106, 120, -37, -119]");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "16efa061a266ee772bb16c5665ef539a5c877e1469db96141540e3c5abbcc9c131985cd09e3722baec6fee8621109ca7" + "'", str3, "16efa061a266ee772bb16c5665ef539a5c877e1469db96141540e3c5abbcc9c131985cd09e3722baec6fee8621109ca7");
    }

    @Test
    public void test2009() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2009");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic0 = new org.apache.commons.codec.language.ColognePhonetic();
        java.lang.String str2 = colognePhonetic0.colognePhonetic("079564");
        boolean boolean5 = colognePhonetic0.isEncodeEqual("e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98", "08cbbefd7b26d3154a21bc6e1b5321a8c22c830337e001d4268209436634ecbc775f850edebd99c4f6e7917f1832ace43c52c5e4d4b15bf10bf8f455889d4628");
        boolean boolean8 = colognePhonetic0.isEncodeEqual("c6699c7aa4c4899a7838b6472b6ae7719eda306fc3de2abefd814d5909c178da", "10101000111111110100010000111000000101000010010100111111011010001010100100100111001010010011101000010111011100000111001111101101010101011101000001101100000110100001010101000110001000101110010100100110101110111101101110100110111101111000011011100010001101011000111101100100000000000010010101011111010101110100101010100100101111101110010101100100101101011111011000011110100011110010110111100010110011110100010000111001100101010000001110001001111010010011011101101110011000110000111100110100011000101010100110111101");
        java.lang.String str10 = colognePhonetic0.colognePhonetic("52106e5d8bc7f95a39ebd909f7d0eb90ab9753c8c85815e28328dff4");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "" + "'", str2, "");
        org.junit.Assert.assertTrue("'" + boolean5 + "' != '" + false + "'", boolean5 == false);
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "02183123211823" + "'", str10, "02183123211823");
    }

    @Test
    public void test2010() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2010");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(byteArray1);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[99, 75, -19, -76, -91, 73, 31, -82, 53, -55, 126, 22, -40, -16, -34, -57, 30, -65, -104, 102, 95, 72, -19, 98, 121, 74, 59, 85]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[89, 48, 118, 116, 116, 75, 86, 74, 72, 54, 52, 49, 121, 88, 52, 87, 50, 80, 68, 101, 120, 120, 54, 95, 109, 71, 90, 102, 83, 79, 49, 105, 101, 85, 111, 55, 86, 81]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[94, -25, 63, 120, -70, -101, -42, 97, -94, 20, 84, -13, -4, -71, 28, 66, 12, -46, 53, -85]");
    }

    @Test
    public void test2011() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2011");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        pureJavaCrc32C0.update(0);
        pureJavaCrc32C0.update((int) '-');
    }

    @Test
    public void test2012() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2012");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec2 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray8, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str12 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray8);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray8);
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray8);
        java.lang.Object obj15 = quotedPrintableCodec2.decode((java.lang.Object) byteArray8);
        java.lang.String str16 = quotedPrintableCodec2.getDefaultCharset();
        java.lang.String str17 = quotedPrintableCodec2.getDefaultCharset();
        java.lang.String str19 = quotedPrintableCodec2.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.apache.commons.codec.net.URLCodec uRLCodec21 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet22 = null;
        byte[] byteArray24 = new byte[] { (byte) 100 };
        byte[] byteArray25 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet22, byteArray24);
        byte[] byteArray26 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray25);
        byte[] byteArray27 = uRLCodec21.encode(byteArray26);
        int int28 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray26);
        byte[] byteArray29 = quotedPrintableCodec2.encode(byteArray26);
        byte[] byteArray30 = org.apache.commons.codec.binary.BinaryCodec.fromAscii(byteArray29);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32 base32_33 = new org.apache.commons.codec.binary.Base32((int) (byte) 0, byteArray29, true, (byte) 100);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: pad must not be in alphabet or whitespace");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str11, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "AAAAAAA" + "'", str12, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str13, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str14, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj15);
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "UTF-8" + "'", str16, "UTF-8");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "UTF-8" + "'", str17, "UTF-8");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str19, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[100]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[100]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertTrue("'" + int28 + "' != '" + (-690116322) + "'", int28 == (-690116322));
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[70, 104, 61, 56, 57, 118, 61, 56, 50, 61, 67, 67, 61, 68, 50, 61, 66, 49, 61, 69, 69, 61, 48, 67, 61, 65, 69, 61, 56, 68, 61, 67, 53, 89, 71, 41, 61, 49, 70, 61, 56, 49, 61, 57, 67, 61, 67, 53, 61, 57, 69, 61, 69, 49, 38, 61, 70, 53, 61, 66, 68, 36, 59, 61, 49, 56, 82, 87, 116, 61, 49, 52, 65, 61, 13, 10, 58, 61, 69, 69, 61, 68, 53, 120, 61, 48, 66, 95, 61, 66, 49, 61, 49, 48, 61, 57, 48, 61, 48, 51, 61, 56, 55, 61, 49, 53, 61, 66, 69, 61, 69, 68, 61, 49, 66, 61, 48, 48, 113, 74, 61, 49, 53, 61, 66, 51, 61, 49, 67, 61, 56, 68, 61, 57, 54, 116, 61, 70, 66, 61, 68, 66, 61, 68, 70, 61, 55, 70, 61, 68, 52, 61, 13, 10, 61, 49, 57, 61, 49, 67]");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[18, 0, 0, 0, 65, 64, -128, 0, 40, 0, 0, -126, 0, 4, 64, 4, 0, 64, 0, 0]");
    }

    @Test
    public void test2013() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2013");
        org.apache.commons.codec.binary.Hex hex0 = new org.apache.commons.codec.binary.Hex();
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer3 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, byteBuffer3);
        char[] charArray6 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer3, true);
        byte[] byteArray7 = hex0.decode(byteBuffer3);
        java.lang.Object obj9 = hex0.encode((java.lang.Object) "HmacMD5");
        byte[] byteArray12 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray13 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray12);
        java.io.InputStream inputStream14 = java.io.InputStream.nullInputStream();
        java.lang.String str15 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, inputStream14);
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream16);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream16);
        java.lang.String str19 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, inputStream16);
        byte[] byteArray21 = inputStream16.readNBytes((int) ' ');
        byte[] byteArray23 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray21, true);
        java.lang.String str24 = org.apache.commons.codec.digest.Crypt.crypt(byteArray23);
        org.apache.commons.codec.CodecPolicy codecPolicy27 = org.apache.commons.codec.CodecPolicy.LENIENT;
        org.apache.commons.codec.binary.Base16 base16_28 = new org.apache.commons.codec.binary.Base16(false, codecPolicy27);
        org.apache.commons.codec.binary.Base64 base64_29 = new org.apache.commons.codec.binary.Base64((int) (short) 10, byteArray23, true, codecPolicy27);
        byte[] byteArray30 = hex0.encode(byteArray23);
        java.nio.charset.Charset charset31 = hex0.getCharset();
        java.nio.charset.Charset charset32 = hex0.getCharset();
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer3);
        org.junit.Assert.assertNotNull(messageDigest4);
        org.junit.Assert.assertEquals(messageDigest4.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray6);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray6), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray6), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray6), "[]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertNotNull(obj9);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str15, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str17, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str18, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str19, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[]");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[]");
// flaky:         org.junit.Assert.assertEquals("'" + str24 + "' != '" + "$6$/uuFgPn4$Rt9..svR5OwvZD6TDm/6Gjdfx04dkWZFt7jm.mkPwRc0KutU./S4Szmuc5Cs3tISFUZcYyrUPs4viiaoXuTFK0" + "'", str24, "$6$/uuFgPn4$Rt9..svR5OwvZD6TDm/6Gjdfx04dkWZFt7jm.mkPwRc0KutU./S4Szmuc5Cs3tISFUZcYyrUPs4viiaoXuTFK0");
        org.junit.Assert.assertTrue("'" + codecPolicy27 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy27.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[]");
        org.junit.Assert.assertNotNull(charset31);
        org.junit.Assert.assertNotNull(charset32);
    }

    @Test
    public void test2014() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2014");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        boolean boolean8 = base32_1.isInAlphabet(byteArray6, false);
        byte[] byteArray10 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str11 = base32_1.encodeAsString(byteArray10);
        java.security.MessageDigest messageDigest12 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        java.security.MessageDigest messageDigest13 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream14 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest15 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest13, inputStream14);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream14);
        byte[] byteArray17 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream14);
        java.security.MessageDigest messageDigest18 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest12, inputStream14);
        java.lang.String str19 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray10, inputStream14);
        byte[] byteArray20 = org.apache.commons.codec.digest.DigestUtils.md2(inputStream14);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream21 = new org.apache.commons.codec.binary.Base16InputStream(inputStream14);
        byte[] byteArray22 = org.apache.commons.codec.digest.DigestUtils.sha3_224(inputStream14);
        byte[] byteArray23 = org.apache.commons.codec.digest.DigestUtils.sha512(inputStream14);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "ABUAA2IAEE======" + "'", str11, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(messageDigest12);
        org.junit.Assert.assertEquals(messageDigest12.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest13);
        org.junit.Assert.assertEquals(messageDigest13.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream14);
        org.junit.Assert.assertNotNull(messageDigest15);
        org.junit.Assert.assertEquals(messageDigest15.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str16, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(messageDigest18);
        org.junit.Assert.assertEquals(messageDigest18.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "ad1cae68ff9c689626df1f53ac8960047f9bd8ff" + "'", str19, "ad1cae68ff9c689626df1f53ac8960047f9bd8ff");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[-125, 80, -27, -93, -30, 76, 21, 61, -14, 39, 92, -97, -128, 105, 39, 115]");
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[107, 78, 3, 66, 54, 103, -37, -73, 59, 110, 21, 69, 79, 14, -79, -85, -44, 89, 127, -102, 27, 7, -114, 63, 91, 90, 107, -57]");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[-49, -125, -31, 53, 126, -17, -72, -67, -15, 84, 40, 80, -42, 109, -128, 7, -42, 32, -28, 5, 11, 87, 21, -36, -125, -12, -87, 33, -45, 108, -23, -50, 71, -48, -47, 60, 93, -123, -14, -80, -1, -125, 24, -46, -121, 126, -20, 47, 99, -71, 49, -67, 71, 65, 122, -127, -91, 56, 50, 122, -7, 39, -38, 62]");
    }

    @Test
    public void test2015() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2015");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        boolean boolean3 = doubleMetaphone0.isDoubleMetaphoneEqual("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "7664fbe062101db016383ccc7d71037a073342cb0a161828f86315b6b9b06ed4053486c8d4f60dd3eb5eefa806facff24d12a98529fe15a02e986cca332ce518");
        java.lang.String str5 = doubleMetaphone0.doubleMetaphone("ash");
        boolean boolean9 = doubleMetaphone0.isDoubleMetaphoneEqual("04757d4fa902aaf10b68a038a265fedc637220bdc9a751747bbb6e3882f24078", "Ptz9RTz3KVvV2", false);
        java.lang.String str11 = doubleMetaphone0.encode("fa0ab302e8502bdf706a9c45df0c8842");
        java.lang.String str13 = doubleMetaphone0.doubleMetaphone("$6$mPBymwvz$8BKX7YMYJAopwDuhFXw.J4bVHToRmmRv2ZPqdUe.IDI.REiA6Zxa6PCgO4BuDb4VkPIP8SHsZVpUZoZ2w/AZn0");
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "AX" + "'", str5, "AX");
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + false + "'", boolean9 == false);
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "FPPT" + "'", str11, "FPPT");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "MPMF" + "'", str13, "MPMF");
    }

    @Test
    public void test2016() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2016");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512("PKKMYF");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[44, -113, -116, -50, 77, -54, -51, -93, -59, 78, 38, 31, -71, 22, 58, 119, 30, 61, -89, 86, 30, 5, -60, 19, 61, -11, -64, 57, 64, 23, 90, 30, -65, 30, 109, 28, 71, -50, 23, 18, 63, -93, 101, 72, -30, 5, 64, 101, 69, -25, -84, 116, -99, -64, -39, 119, 85, -1, -21, -3, -109, 90, -48, 72]");
    }

    @Test
    public void test2017() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2017");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray4);
        xXHash32_0.update(byteArray6, (int) (byte) 10, (-690116322));
        byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.sha3_224("SHA3-256");
        byte[] byteArray12 = org.apache.commons.codec.net.URLCodec.decodeUrl(byteArray11);
        java.security.MessageDigest messageDigest13 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream14 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest15 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest13, inputStream14);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream14);
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(inputStream14);
        byte[] byteArray21 = org.apache.commons.codec.digest.DigestUtils.sha512("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        org.apache.commons.codec.binary.Base32 base32_23 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet24 = null;
        byte[] byteArray26 = new byte[] { (byte) 100 };
        byte[] byteArray27 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet24, byteArray26);
        byte[] byteArray28 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray27);
        boolean boolean30 = base32_23.isInAlphabet(byteArray28, false);
        org.apache.commons.codec.CodecPolicy codecPolicy31 = base32_23.getCodecPolicy();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream32 = new org.apache.commons.codec.binary.Base32InputStream(inputStream14, false, (-965378730), byteArray21, codecPolicy31);
        org.apache.commons.codec.binary.Base32InputStream base32InputStream34 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base32InputStream32, false);
        byte[] byteArray35 = org.apache.commons.codec.digest.HmacUtils.hmacMd5(byteArray11, (java.io.InputStream) base32InputStream34);
        java.lang.String str36 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray11);
        xXHash32_0.update(byteArray11);
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertNotNull(messageDigest13);
        org.junit.Assert.assertEquals(messageDigest13.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream14);
        org.junit.Assert.assertNotNull(messageDigest15);
        org.junit.Assert.assertEquals(messageDigest15.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str16, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str17, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[-23, -79, 11, -33, -89, -101, -39, -8, -117, -105, -106, -5, -21, -106, 50, -56, 21, 18, -61, -114, 105, 80, -19, -101, 10, -56, -40, -85, 92, -106, -81, -9, -50, -69, 98, -2, -85, -107, -112, -42, -17, -116, -95, 49, -86, 28, 11, -23, -119, -50, -86, -49, 59, 89, 81, 51, -52, -123, 46, -91, -69, 38, -16, -69]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[100]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[100]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean30 + "' != '" + false + "'", boolean30 == false);
        org.junit.Assert.assertTrue("'" + codecPolicy31 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy31.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[-11, -28, -76, -63, -66, 3, -93, -25, 111, -5, 6, -115, 6, -97, 60, 21]");
// flaky:         org.junit.Assert.assertEquals("'" + str36 + "' != '" + "DBTJv5Zi93HCM" + "'", str36, "DBTJv5Zi93HCM");
    }

    @Test
    public void test2018() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2018");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray4);
        pureJavaCrc32C0.update(byteArray4, (-690116322), (-1612190696));
        byte[] byteArray11 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray12 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray11);
        pureJavaCrc32C0.update(byteArray11);
        byte[] byteArray19 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray19);
        java.lang.String str22 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray19, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str23 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray19);
        byte[] byteArray24 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray11, byteArray19);
        java.util.BitSet bitSet25 = null;
        byte[] byteArray27 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray28 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet25, byteArray27);
        java.lang.String str29 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray27);
        byte[] byteArray30 = org.apache.commons.codec.digest.HmacUtils.hmacSha512(byteArray11, byteArray27);
        byte[] byteArray34 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray11, false, true, (int) '4');
        byte[] byteArray35 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray34);
        byte[] byteArray41 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str42 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray41);
        java.lang.String str44 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray41, "99448658175a0534e08dbca1fe67b58231a53eec");
        byte[] byteArray45 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray41);
        java.lang.String str47 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray45, true);
        java.lang.String str48 = org.apache.commons.codec.binary.BinaryCodec.toAsciiString(byteArray45);
        java.lang.String str49 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex(byteArray35, byteArray45);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str20, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str22, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "AAAAAAA" + "'", str23, "AAAAAAA");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[44, 25, 81, 48, 24, -86, -111, -40, 44, -103, -115, 18, -39, 13, 31, -4, 55, -9, 40, 4, 100, -72, 12, -2, -68, 111, -122, -91, 123, -78, -42, 39, -106, -105, 87, -15, -32, 60, 52, -87, 78, 32, 122, 96, 104, 91, 55, -81]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[]");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str29, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[-64, 47, 34, -10, 1, 61, 18, 22, 38, -97, -55, -115, 61, -75, 58, -117, -128, -125, 0, 106, 79, 53, 123, 29, -33, -113, -3, 11, 77, -35, 82, -15, 94, 30, -57, 56, 70, -51, -30, 45, 25, 88, 74, -92, -32, -76, 109, -49, -73, -74, 71, -87, -65, 110, 78, -75, -56, -89, 14, 51, -22, -30, 65, -78]");
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[65, 71, 103, 65, 97, 81, 65, 104]");
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[-128, -99, 2, 87, -9, 5, -30, -7, -49, 20, -52, -33, -127, -126, 34, -37, -20, -119, 70, -86, 20, -32, 98, 84, -29, 109, 122, 69, -77, -78, -72, -108]");
        org.junit.Assert.assertNotNull(byteArray41);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray41), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str42 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str42, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str44 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str44, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertNotNull(byteArray45);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray45), "[-67, -87, 98, 52, 15, 99, 110, 55, -23, -119, 3, -107, 57, 68, -49, -30, 45, -113, 30, -10, -75, 100, -27, -66, -92, 74, 87, 95, 37, 0, 100, -113, 53, -30, -122, -9, -90, -37, -69, 38, -27, 34, 70, 21, 26, 108, -48, 85, -19, 115, 112, 23, 58, 41, 39, -87, 104, 63, 37, 20, 56, 68, -1, -88]");
        org.junit.Assert.assertEquals("'" + str47 + "' != '" + "bda962340f636e37e98903953944cfe22d8f1ef6b564e5bea44a575f2500648f35e286f7a6dbbb26e52246151a6cd055ed7370173a2927a9683f25143844ffa8" + "'", str47, "bda962340f636e37e98903953944cfe22d8f1ef6b564e5bea44a575f2500648f35e286f7a6dbbb26e52246151a6cd055ed7370173a2927a9683f25143844ffa8");
        org.junit.Assert.assertEquals("'" + str48 + "' != '" + "10101000111111110100010000111000000101000010010100111111011010001010100100100111001010010011101000010111011100000111001111101101010101011101000001101100000110100001010101000110001000101110010100100110101110111101101110100110111101111000011011100010001101011000111101100100000000000010010101011111010101110100101010100100101111101110010101100100101101011111011000011110100011110010110111100010110011110100010000111001100101010000001110001001111010010011011101101110011000110000111100110100011000101010100110111101" + "'", str48, "10101000111111110100010000111000000101000010010100111111011010001010100100100111001010010011101000010111011100000111001111101101010101011101000001101100000110100001010101000110001000101110010100100110101110111101101110100110111101111000011011100010001101011000111101100100000000000010010101011111010101110100101010100100101111101110010101100100101101011111011000011110100011110010110111100010110011110100010000111001100101010000001110001001111010010011011101101110011000110000111100110100011000101010100110111101");
        org.junit.Assert.assertEquals("'" + str49 + "' != '" + "511c36d7769c77f7b5e37217dbeb4d2edbef1dd6bfaf5c93b00f2490cf67d807aa66a709133272dfd14ea5c39e006e08" + "'", str49, "511c36d7769c77f7b5e37217dbeb4d2edbef1dd6bfaf5c93b00f2490cf67d807aa66a709133272dfd14ea5c39e006e08");
    }

    @Test
    public void test2019() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2019");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf8("ABUAA2IAEE======");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray1);
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils4 = new org.apache.commons.codec.digest.DigestUtils(messageDigest3);
        java.security.MessageDigest messageDigest5 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream6 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest7 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest5, inputStream6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream6);
        byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream6);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream10 = new org.apache.commons.codec.binary.Base16InputStream(inputStream6);
        byte[] byteArray11 = digestUtils4.digest(inputStream6);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray1, inputStream6);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[65, 66, 85, 65, 65, 50, 73, 65, 69, 69, 61, 61, 61, 61, 61, 61]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[100, -90, -97, -54, 36, -31, 6, -35, -93, 46, 55, 97, 67, -33, -90, 13, 70, 71, 10, -74, -99, 44, 47, -11, 3, 8, -16, -99, -101, 58, -107, 51]");
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest5);
        org.junit.Assert.assertEquals(messageDigest5.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream6);
        org.junit.Assert.assertNotNull(messageDigest7);
        org.junit.Assert.assertEquals(messageDigest7.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str8, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "2e1cda1c04c3a170e7da6f8df6bcfc2ca2aa1387ceaae0af76c4a1f3604d5cdb0523efa6e62607f93e59dcec68a390ad8850185cb421fec9b8bdd5bbc8c41764" + "'", str12, "2e1cda1c04c3a170e7da6f8df6bcfc2ca2aa1387ceaae0af76c4a1f3604d5cdb0523efa6e62607f93e59dcec68a390ad8850185cb421fec9b8bdd5bbc8c41764");
    }

    @Test
    public void test2020() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2020");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384("");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.md2Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "a42d3298fc52019dcd57ab90120c7670" + "'", str2, "a42d3298fc52019dcd57ab90120c7670");
    }

    @Test
    public void test2021() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2021");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        java.lang.String str4 = qCodec3.getDefaultCharset();
        java.nio.charset.Charset charset5 = qCodec3.getCharset();
        qCodec3.setEncodeBlanks(true);
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "UTF-8" + "'", str4, "UTF-8");
        org.junit.Assert.assertNotNull(charset5);
    }

    @Test
    public void test2022() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2022");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray4);
        pureJavaCrc32C0.update(byteArray4, (-690116322), (-1612190696));
        org.apache.commons.codec.net.URLCodec uRLCodec11 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet12 = null;
        byte[] byteArray14 = new byte[] { (byte) 100 };
        byte[] byteArray15 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet12, byteArray14);
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray15);
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray15);
        byte[] byteArray18 = uRLCodec11.decode(byteArray15);
        byte[] byteArray19 = null;
        byte[] byteArray20 = uRLCodec11.decode(byteArray19);
        byte[] byteArray26 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str27 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray26);
        java.lang.String str29 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray26, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_30 = new org.apache.commons.codec.binary.Base16();
        boolean boolean32 = base16_30.isInAlphabet("AAAAAAA");
        byte[] byteArray36 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str38 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray36, true);
        java.lang.String str39 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray36);
        boolean boolean41 = base16_30.isInAlphabet(byteArray36, true);
        byte[] byteArray42 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray26, byteArray36);
        byte[] byteArray43 = uRLCodec11.encode(byteArray42);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec45 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray51 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str52 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray51);
        java.lang.String str54 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray51, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str55 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray51);
        java.lang.String str56 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray51);
        java.lang.String str57 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray51);
        java.lang.Object obj58 = quotedPrintableCodec45.decode((java.lang.Object) byteArray51);
        byte[] byteArray59 = uRLCodec11.encode(byteArray51);
        java.io.OutputStream outputStream60 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream61 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream60);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream63 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream61, true);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream65 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream61, true);
        org.apache.commons.codec.digest.XXHash32 xXHash32_68 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet69 = null;
        byte[] byteArray71 = new byte[] { (byte) 100 };
        byte[] byteArray72 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet69, byteArray71);
        byte[] byteArray73 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray72);
        byte[] byteArray74 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray72);
        xXHash32_68.update(byteArray74, (int) (byte) 10, (-690116322));
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream78 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream61, true, 760066800, byteArray74);
        java.security.MessageDigest messageDigest79 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream80 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest81 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest79, inputStream80);
        java.lang.String str82 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream80);
        byte[] byteArray83 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream80);
        java.lang.String str84 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex(byteArray74, inputStream80);
        java.lang.String str85 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray51, inputStream80);
        byte[] byteArray87 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray88 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray87);
        java.io.InputStream inputStream89 = java.io.InputStream.nullInputStream();
        java.lang.String str90 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray88, inputStream89);
        java.io.InputStream inputStream91 = java.io.InputStream.nullInputStream();
        java.lang.String str92 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream91);
        java.lang.String str93 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream91);
        java.lang.String str94 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray88, inputStream91);
        byte[] byteArray95 = org.apache.commons.codec.digest.HmacUtils.hmacSha1(byteArray51, inputStream91);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str96 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray4, inputStream91);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[100]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[100]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str17, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[100]");
        org.junit.Assert.assertNull(byteArray20);
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str27, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str29, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean32 + "' != '" + true + "'", boolean32 == true);
        org.junit.Assert.assertNotNull(byteArray36);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray36), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str38 + "' != '" + "ffffff" + "'", str38, "ffffff");
        org.junit.Assert.assertEquals("'" + str39 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str39, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean41 + "' != '" + false + "'", boolean41 == false);
        org.junit.Assert.assertNotNull(byteArray42);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray42), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray43);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray43), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
        org.junit.Assert.assertNotNull(byteArray51);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray51), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str52 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str52, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str54 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str54, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str55 + "' != '" + "AAAAAAA" + "'", str55, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str56 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str56, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str57 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str57, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj58);
        org.junit.Assert.assertNotNull(byteArray59);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray59), "[37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48]");
        org.junit.Assert.assertNotNull(outputStream60);
        org.junit.Assert.assertNotNull(byteArray71);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray71), "[100]");
        org.junit.Assert.assertNotNull(byteArray72);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray72), "[100]");
        org.junit.Assert.assertNotNull(byteArray73);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray73), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray74);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray74), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(messageDigest79);
        org.junit.Assert.assertEquals(messageDigest79.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream80);
        org.junit.Assert.assertNotNull(messageDigest81);
        org.junit.Assert.assertEquals(messageDigest81.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str82 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str82, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray83);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray83), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertEquals("'" + str84 + "' != '" + "c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a" + "'", str84, "c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a");
        org.junit.Assert.assertEquals("'" + str85 + "' != '" + "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d" + "'", str85, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
        org.junit.Assert.assertNotNull(byteArray87);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray87), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray88);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray88), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream89);
        org.junit.Assert.assertEquals("'" + str90 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str90, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream91);
        org.junit.Assert.assertEquals("'" + str92 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str92, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str93 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str93, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str94 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str94, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray95);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray95), "[-5, -37, 29, 27, 24, -86, 108, 8, 50, 75, 125, 100, -73, 31, -73, 99, 112, 105, 14, 29]");
    }

    @Test
    public void test2023() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2023");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray5);
        byte[] byteArray13 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray14 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray13);
        java.io.InputStream inputStream15 = java.io.InputStream.nullInputStream();
        java.lang.String str16 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray14, inputStream15);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream17 = new org.apache.commons.codec.binary.Base64InputStream(inputStream15);
        int int18 = base64InputStream17.available();
        byte[] byteArray19 = org.apache.commons.codec.digest.HmacUtils.hmacSha1(byteArray5, (java.io.InputStream) base64InputStream17);
        char[] charArray20 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str11, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream15);
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str16, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertTrue("'" + int18 + "' != '" + 1 + "'", int18 == 1);
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[-5, -37, 29, 27, 24, -86, 108, 8, 50, 75, 125, 100, -73, 31, -73, 99, 112, 105, 14, 29]");
        org.junit.Assert.assertNotNull(charArray20);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray20), "0000000000000000000000000000000000000000");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray20), "0000000000000000000000000000000000000000");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray20), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
    }

    @Test
    public void test2024() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2024");
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest2);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms4 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet5 = null;
        byte[] byteArray7 = new byte[] { (byte) 100 };
        byte[] byteArray8 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet5, byteArray7);
        byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray8);
        javax.crypto.Mac mac10 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms4, byteArray9);
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        java.lang.String str19 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray16, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str20 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray16);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray16);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray16);
        javax.crypto.Mac mac23 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms4, byteArray16);
        org.apache.commons.codec.binary.Base32 base32_25 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet26 = null;
        byte[] byteArray28 = new byte[] { (byte) 100 };
        byte[] byteArray29 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet26, byteArray28);
        byte[] byteArray30 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray29);
        boolean boolean32 = base32_25.isInAlphabet(byteArray30, false);
        byte[] byteArray34 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str35 = base32_25.encodeAsString(byteArray34);
        org.apache.commons.codec.digest.HmacUtils hmacUtils36 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms4, byteArray34);
        java.security.MessageDigest messageDigest37 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest3, byteArray34);
        org.apache.commons.codec.digest.DigestUtils digestUtils38 = new org.apache.commons.codec.digest.DigestUtils(messageDigest37);
        java.security.MessageDigest messageDigest39 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream40 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest41 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest39, inputStream40);
        java.nio.ByteBuffer byteBuffer43 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        byte[] byteArray44 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest41, byteBuffer43);
        java.lang.String str45 = digestUtils38.digestAsHex(byteBuffer43);
        org.apache.commons.codec.digest.XXHash32 xXHash32_46 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet47 = null;
        byte[] byteArray49 = new byte[] { (byte) 100 };
        byte[] byteArray50 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet47, byteArray49);
        byte[] byteArray51 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray50);
        byte[] byteArray52 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray50);
        xXHash32_46.update(byteArray52, (int) (byte) 10, (-690116322));
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec57 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray63 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str64 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray63);
        java.lang.String str66 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray63, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str67 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray63);
        java.lang.String str68 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray63);
        java.lang.String str69 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray63);
        java.lang.Object obj70 = quotedPrintableCodec57.decode((java.lang.Object) byteArray63);
        java.lang.String str71 = quotedPrintableCodec57.getDefaultCharset();
        java.lang.String str72 = quotedPrintableCodec57.getDefaultCharset();
        java.lang.String str74 = quotedPrintableCodec57.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.apache.commons.codec.net.URLCodec uRLCodec76 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet77 = null;
        byte[] byteArray79 = new byte[] { (byte) 100 };
        byte[] byteArray80 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet77, byteArray79);
        byte[] byteArray81 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray80);
        byte[] byteArray82 = uRLCodec76.encode(byteArray81);
        int int83 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray81);
        byte[] byteArray84 = quotedPrintableCodec57.encode(byteArray81);
        java.lang.String str85 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray52, byteArray84);
        byte[] byteArray86 = digestUtils38.digest(byteArray84);
        boolean boolean87 = org.apache.commons.codec.binary.Base64.isBase64(byteArray84);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_88 = new org.apache.commons.codec.binary.Base64((int) '-', byteArray84);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [Fh=89v=82=CC=D2=B1=EE=0C=AE=8D=C5YG)=1F=81=9C=C5=9E=E1&=F5=BD$;=18RWt=14A=??:=EE=D5x=0B_=B1=10=90=03=87=15=BE=ED=1B=00qJ=15=B3=1C=8D=96t=FB=DB=DF=7F=D4=??=19=1C]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms4 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms4.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac10);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str19, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "AAAAAAA" + "'", str20, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str21, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str22, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac23);
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[100]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[100]");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean32 + "' != '" + false + "'", boolean32 == false);
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str35 + "' != '" + "ABUAA2IAEE======" + "'", str35, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(messageDigest37);
        org.junit.Assert.assertEquals(messageDigest37.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest39);
        org.junit.Assert.assertEquals(messageDigest39.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream40);
        org.junit.Assert.assertNotNull(messageDigest41);
        org.junit.Assert.assertEquals(messageDigest41.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteBuffer43);
        org.junit.Assert.assertNotNull(byteArray44);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray44), "[95, 64, -81, 13, 25, -127, -108, 67, 56, -44, -88, -75, -99, -26, -30, 113, 23, 21, 27, -41, 118, 105, 115, 47, 101, 11, 38, -60, 92, 74, -64, -41, 6, 12, 32, 127, -27, 36, 65, -15, -87, -50, -127, 34, -41, -17, 116, -114, -90, -124, -31, -3, -42, -50, 73, 70, -5, 101, -75, -58, -79, 57, -126, 119]");
        org.junit.Assert.assertEquals("'" + str45 + "' != '" + "01118df906a97646cfc8587e18c99189855dea2d3a76ecfbf9b9716d6bff07952c55e6320079cc7b6e353b0718c3effe" + "'", str45, "01118df906a97646cfc8587e18c99189855dea2d3a76ecfbf9b9716d6bff07952c55e6320079cc7b6e353b0718c3effe");
        org.junit.Assert.assertNotNull(byteArray49);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray49), "[100]");
        org.junit.Assert.assertNotNull(byteArray50);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray50), "[100]");
        org.junit.Assert.assertNotNull(byteArray51);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray51), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray52);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray52), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray63);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray63), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str64 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str64, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str66 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str66, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str67 + "' != '" + "AAAAAAA" + "'", str67, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str68 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str68, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str69 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str69, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj70);
        org.junit.Assert.assertEquals("'" + str71 + "' != '" + "UTF-8" + "'", str71, "UTF-8");
        org.junit.Assert.assertEquals("'" + str72 + "' != '" + "UTF-8" + "'", str72, "UTF-8");
        org.junit.Assert.assertEquals("'" + str74 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str74, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(byteArray79);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray79), "[100]");
        org.junit.Assert.assertNotNull(byteArray80);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray80), "[100]");
        org.junit.Assert.assertNotNull(byteArray81);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray81), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray82);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray82), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertTrue("'" + int83 + "' != '" + (-690116322) + "'", int83 == (-690116322));
        org.junit.Assert.assertNotNull(byteArray84);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray84), "[70, 104, 61, 56, 57, 118, 61, 56, 50, 61, 67, 67, 61, 68, 50, 61, 66, 49, 61, 69, 69, 61, 48, 67, 61, 65, 69, 61, 56, 68, 61, 67, 53, 89, 71, 41, 61, 49, 70, 61, 56, 49, 61, 57, 67, 61, 67, 53, 61, 57, 69, 61, 69, 49, 38, 61, 70, 53, 61, 66, 68, 36, 59, 61, 49, 56, 82, 87, 116, 61, 49, 52, 65, 61, 13, 10, 58, 61, 69, 69, 61, 68, 53, 120, 61, 48, 66, 95, 61, 66, 49, 61, 49, 48, 61, 57, 48, 61, 48, 51, 61, 56, 55, 61, 49, 53, 61, 66, 69, 61, 69, 68, 61, 49, 66, 61, 48, 48, 113, 74, 61, 49, 53, 61, 66, 51, 61, 49, 67, 61, 56, 68, 61, 57, 54, 116, 61, 70, 66, 61, 68, 66, 61, 68, 70, 61, 55, 70, 61, 68, 52, 61, 13, 10, 61, 49, 57, 61, 49, 67]");
        org.junit.Assert.assertEquals("'" + str85 + "' != '" + "4c98f32a81be34128784b1e12b12b6d0067344e3e7697e56b3132f7a0ce68b473defef83edcaf80923730064ca2318078fbb9fa3444ce5ddcda20d72d173ac1d" + "'", str85, "4c98f32a81be34128784b1e12b12b6d0067344e3e7697e56b3132f7a0ce68b473defef83edcaf80923730064ca2318078fbb9fa3444ce5ddcda20d72d173ac1d");
        org.junit.Assert.assertNotNull(byteArray86);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray86), "[64, 44, -14, -25, -5, 124, -64, 69, 19, -50, 27, -65, 78, -31, 39, 80, -17, 92, -2, -19, -99, 80, 90, 95, -45, -94, -121, 90, 123, -68, -14, -80, -52, -21, 18, -20, 102, 30, 104, 47, 17, 24, -67, 72, -39, 125, 27, 94]");
        org.junit.Assert.assertTrue("'" + boolean87 + "' != '" + false + "'", boolean87 == false);
    }

    @Test
    public void test2025() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2025");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.Charsets.US_ASCII;
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec2 = new org.apache.commons.codec.net.QuotedPrintableCodec(charset0, false);
        java.io.OutputStream outputStream3 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream4 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream3);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec8 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray14 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray14);
        java.lang.String str17 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray14, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str18 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray14);
        java.lang.String str19 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray14);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray14);
        java.lang.Object obj21 = quotedPrintableCodec8.decode((java.lang.Object) byteArray14);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream22 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream4, true, 1, byteArray14);
        byte[] byteArray27 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str28 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray27);
        java.lang.String str29 = org.apache.commons.codec.binary.StringUtils.newStringUtf16Be(byteArray27);
        java.nio.charset.Charset charset30 = org.apache.commons.codec.Charsets.UTF_16;
        org.apache.commons.codec.binary.Base64 base64_32 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy33 = base64_32.getCodecPolicy();
        org.apache.commons.codec.net.BCodec bCodec34 = new org.apache.commons.codec.net.BCodec(charset30, codecPolicy33);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream35 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream4, true, (int) (short) 1, byteArray27, codecPolicy33);
        org.apache.commons.codec.net.BCodec bCodec36 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy33);
        org.apache.commons.codec.net.QCodec qCodec37 = new org.apache.commons.codec.net.QCodec(charset0);
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(outputStream3);
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str15, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str17, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "AAAAAAA" + "'", str18, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str19, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str20, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj21);
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str28 + "' != '" + "\000\ufffd" + "'", str28, "\000\ufffd");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "\377" + "'", str29, "\377");
        org.junit.Assert.assertNotNull(charset30);
        org.junit.Assert.assertTrue("'" + codecPolicy33 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy33.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test2026() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2026");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_512("0931291c985a15d86bf406276121461af7e4553d");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[28, -105, -45, -102, 48, -68, -120, -116, 48, -12, 101, 87, 68, 59, -115, -65, -25, -37, -15, -112, -105, -116, 22, 55, -103, -20, 5, -49, 101, -109, -15, 81, -48, -123, 101, 88, -116, 16, -115, 46, 86, -55, 55, -104, -38, -38, 123, 100, -88, -29, 79, -68, -63, 116, -45, 123, -32, 56, 78, 42, 117, -11, -83, -13]");
    }

    @Test
    public void test2027() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2027");
        org.apache.commons.codec.net.PercentCodec percentCodec0 = new org.apache.commons.codec.net.PercentCodec();
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec2 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray8, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str12 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray8);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray8);
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray8);
        java.lang.Object obj15 = quotedPrintableCodec2.decode((java.lang.Object) byteArray8);
        java.lang.String str16 = quotedPrintableCodec2.getDefaultCharset();
        byte[] byteArray18 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray19 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray18);
        java.io.InputStream inputStream20 = java.io.InputStream.nullInputStream();
        java.lang.String str21 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray19, inputStream20);
        java.io.InputStream inputStream22 = java.io.InputStream.nullInputStream();
        java.lang.String str23 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream22);
        java.lang.String str24 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream22);
        java.lang.String str25 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray19, inputStream22);
        java.lang.Object obj26 = quotedPrintableCodec2.encode((java.lang.Object) byteArray19);
        byte[] byteArray27 = percentCodec0.encode(byteArray19);
        // The following exception was thrown during execution in test generation
        try {
            int int30 = org.apache.commons.codec.digest.MurmurHash2.hash32(byteArray19, (-36807446), 76);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -36807447 out of bounds for length 10");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str11, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "AAAAAAA" + "'", str12, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str13, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str14, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj15);
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "UTF-8" + "'", str16, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream20);
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str21, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream22);
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str23, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str24, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str25, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(obj26);
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
    }

    @Test
    public void test2028() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2028");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms3 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        javax.crypto.Mac mac9 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms3, byteArray8);
        byte[] byteArray15 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray15);
        java.lang.String str18 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray15, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str19 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray15);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray15);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray15);
        javax.crypto.Mac mac22 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms3, byteArray15);
        org.apache.commons.codec.binary.Base32 base32_24 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet25 = null;
        byte[] byteArray27 = new byte[] { (byte) 100 };
        byte[] byteArray28 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet25, byteArray27);
        byte[] byteArray29 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray28);
        boolean boolean31 = base32_24.isInAlphabet(byteArray29, false);
        byte[] byteArray33 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str34 = base32_24.encodeAsString(byteArray33);
        org.apache.commons.codec.digest.HmacUtils hmacUtils35 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms3, byteArray33);
        java.security.MessageDigest messageDigest36 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest2, byteArray33);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms37 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet38 = null;
        byte[] byteArray40 = new byte[] { (byte) 100 };
        byte[] byteArray41 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet38, byteArray40);
        byte[] byteArray42 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray41);
        javax.crypto.Mac mac43 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms37, byteArray42);
        byte[] byteArray49 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str50 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray49);
        java.lang.String str52 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray49, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str53 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray49);
        java.lang.String str54 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray49);
        java.lang.String str55 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray49);
        javax.crypto.Mac mac56 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms37, byteArray49);
        org.apache.commons.codec.binary.Base32 base32_58 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet59 = null;
        byte[] byteArray61 = new byte[] { (byte) 100 };
        byte[] byteArray62 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet59, byteArray61);
        byte[] byteArray63 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray62);
        boolean boolean65 = base32_58.isInAlphabet(byteArray63, false);
        byte[] byteArray67 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str68 = base32_58.encodeAsString(byteArray67);
        org.apache.commons.codec.digest.HmacUtils hmacUtils69 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms37, byteArray67);
        java.nio.ByteBuffer byteBuffer71 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        byte[] byteArray72 = hmacUtils69.hmac(byteBuffer71);
        byte[] byteArray73 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest2, byteBuffer71);
        char[] charArray74 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer71);
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms3 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms3.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac9);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str16, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str18, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "AAAAAAA" + "'", str19, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str20, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str21, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac22);
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[100]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[100]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean31 + "' != '" + false + "'", boolean31 == false);
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "ABUAA2IAEE======" + "'", str34, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(messageDigest36);
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms37 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms37.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[100]");
        org.junit.Assert.assertNotNull(byteArray41);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray41), "[100]");
        org.junit.Assert.assertNotNull(byteArray42);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray42), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac43);
        org.junit.Assert.assertNotNull(byteArray49);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray49), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str50 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str50, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str52 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str52, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str53 + "' != '" + "AAAAAAA" + "'", str53, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str54 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str54, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str55 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str55, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac56);
        org.junit.Assert.assertNotNull(byteArray61);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray61), "[100]");
        org.junit.Assert.assertNotNull(byteArray62);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray62), "[100]");
        org.junit.Assert.assertNotNull(byteArray63);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray63), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean65 + "' != '" + false + "'", boolean65 == false);
        org.junit.Assert.assertNotNull(byteArray67);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray67), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str68 + "' != '" + "ABUAA2IAEE======" + "'", str68, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(byteBuffer71);
        org.junit.Assert.assertNotNull(byteArray72);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray72), "[-56, -6, 38, 92, -40, -35, -88, -80, -32, 55, -47, -60, -40, 18, -70, 57, -127, -91, 121, -38, -55, 108, 76, -109, -12, 40, 123, -90]");
        org.junit.Assert.assertNotNull(byteArray73);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray73), "[1, 17, -115, -7, 6, -87, 118, 70, -49, -56, 88, 126, 24, -55, -111, -119, -123, 93, -22, 45, 58, 118, -20, -5, -7, -71, 113, 109, 107, -1, 7, -107, 44, 85, -26, 50, 0, 121, -52, 123, 110, 53, 59, 7, 24, -61, -17, -2]");
        org.junit.Assert.assertNotNull(charArray74);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray74), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray74), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray74), "[]");
    }

    @Test
    public void test2029() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2029");
        byte[] byteArray1 = org.apache.commons.codec.binary.Base64.decodeBase64("$6$YBcl1v8D$gMs7wb0MztJwDjR4F6msVk2Gd6AJXpO1Ho2yyaSWyenySCOFTI3DGRXG5jhHuuJYmBcRk1UKI3g1fwQSdjTES1");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-23, -128, 92, -105, 91, -4, 14, 3, 44, -17, 6, -12, 51, 59, 73, -64, 56, -47, -32, 94, -90, -79, 89, 54, 25, -34, -128, 37, 122, 78, -44, 122, 54, -53, 38, -110, 91, 39, -89, -55, 32, -114, 21, 50, 55, 12, 100, 87, 27, -104, -31, 30, -21, -119, 98, 96, 92, 70, 77, 84, 40, -115, -32, -43, -4, 16, 73, -40, -45, 17, 45]");
    }

    @Test
    public void test2030() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2030");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md2Hex(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test2031() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2031");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256("7516c70c482edf6875ceeebcf2f59b6e1710acbc432fa2c0f4c9551661568709b30b8b3c4025be1396f0885b975b8beba34be8451a6f8adf33ed1480ebd15181");
        char[] charArray3 = org.apache.commons.codec.binary.Hex.encodeHex(byteArray1, true);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[70, -124, 86, 104, -23, 17, -36, 75, 120, 78, 41, -67, -108, 111, -69, -90, -99, -40, 118, -61, -43, -72, 59, -96, 40, 29, -86, -107, -8, -64, 85, 36]");
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "46845668e911dc4b784e29bd946fbba69dd876c3d5b83ba0281daa95f8c05524");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "46845668e911dc4b784e29bd946fbba69dd876c3d5b83ba0281daa95f8c05524");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[4, 6, 8, 4, 5, 6, 6, 8, e, 9, 1, 1, d, c, 4, b, 7, 8, 4, e, 2, 9, b, d, 9, 4, 6, f, b, b, a, 6, 9, d, d, 8, 7, 6, c, 3, d, 5, b, 8, 3, b, a, 0, 2, 8, 1, d, a, a, 9, 5, f, 8, c, 0, 5, 5, 2, 4]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "71e3cff6184458141180fb99f6835db0323cc10f471050de6aae8f07d6a9215eccfa04850a60c5330fae3666d6bfe556dff61c79e4a268a10afa8c00d2a2ccb2" + "'", str4, "71e3cff6184458141180fb99f6835db0323cc10f471050de6aae8f07d6a9215eccfa04850a60c5330fae3666d6bfe556dff61c79e4a268a10afa8c00d2a2ccb2");
    }

    @Test
    public void test2032() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2032");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        org.apache.commons.codec.binary.Base32 base32_2 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray6);
        boolean boolean9 = base32_2.isInAlphabet(byteArray7, false);
        byte[] byteArray10 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray7);
        java.security.MessageDigest messageDigest11 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteArray7);
        java.io.RandomAccessFile randomAccessFile12 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest11, randomAccessFile12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + false + "'", boolean9 == false);
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[82, 109, 105, 74, 100, 111, 76, 77, 48, 114, 72, 117, 68, 75, 54, 78, 120, 86, 108, 72, 75, 82, 43, 66, 110, 77, 87, 101, 52, 83, 98, 49, 118, 83, 81, 55, 71, 70, 74, 88, 100, 66, 82, 66, 79, 117, 55, 86, 101, 65, 116, 102, 115, 82, 67, 81, 65, 52, 99, 86, 118, 117, 48, 98, 65, 72, 70, 75, 70, 98, 77, 99, 106, 90, 90, 48, 13, 10, 43, 57, 118, 102, 102, 57, 81, 90, 72, 65, 61, 61, 13, 10]");
        org.junit.Assert.assertNotNull(messageDigest11);
        org.junit.Assert.assertEquals(messageDigest11.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test2033() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2033");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md5("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        javax.crypto.Mac mac2 = org.apache.commons.codec.digest.HmacUtils.getHmacSha256(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[123, 118, -12, -87, 41, 124, 1, 20, 35, -56, -84, -61, -49, 11, -8, -51]");
        org.junit.Assert.assertNotNull(mac2);
    }

    @Test
    public void test2034() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2034");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha384("\u03c3\ufffd\ufe3d\ufffd\ufffd\ufffd\007\ufffd\ufffd\005\013W\025\u0703\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\030\u0487\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd>");
        org.junit.Assert.assertNotNull(byteArray1);
// flaky:         org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[51, -90, -24, -69, -124, -122, -67, -69, 116, 112, -5, -31, 125, 97, 124, -107, -91, -54, -13, 101, 107, 102, -123, -49, 32, -104, -82, 24, -2, -51, 120, 102, -125, -91, -36, -95, 67, -39, -80, 85, 103, 43, 117, 119, 19, 91, -83, 50]");
    }

    @Test
    public void test2035() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2035");
        boolean boolean1 = org.apache.commons.codec.digest.HmacUtils.isAvailable("PKMF");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test2036() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2036");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        java.io.OutputStream outputStream2 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_4 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream6 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream2, (org.apache.commons.codec.binary.BaseNCodec) base16_4, false);
        byte[] byteArray9 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str10 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray9);
        long long11 = base16_4.getEncodedLength(byteArray9);
        byte[] byteArray12 = digestUtils1.digest(byteArray9);
        java.nio.ByteBuffer byteBuffer14 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        java.lang.String str15 = digestUtils1.digestAsHex(byteBuffer14);
        char[] charArray16 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer14);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(outputStream2);
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "\000\ufffd" + "'", str10, "\000\ufffd");
        org.junit.Assert.assertTrue("'" + long11 + "' != '" + 4L + "'", long11 == 4L);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[118, 16, 18, -102, -37, -99, -101, 93, -121, -6, 112, 76, 20, -78, -89, -111, 104, -101, 56, 39, -120, -81, 72, -106, 82, 11, 76, 29, 47, -108, 35, -72, -58, -24, -103, 19, -66, 1, 77, -23, 89, -100, 93, 116, 115, 18, -91, -9]");
        org.junit.Assert.assertNotNull(byteBuffer14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "3ff957f5f15f4601a47dbcf1ec96f77aef863a3ec334ff6566e85543ec3b5ab947e2aa3f42acfa577178bfe61e2eb393" + "'", str15, "3ff957f5f15f4601a47dbcf1ec96f77aef863a3ec334ff6566e85543ec3b5ab947e2aa3f42acfa577178bfe61e2eb393");
        org.junit.Assert.assertNotNull(charArray16);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray16), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray16), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray16), "[]");
    }

    @Test
    public void test2037() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2037");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("U=QF");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$CyDhj.Ml$um69yhECTjg9Em.BvP6LRvqqWFKalIM5tWeXlddpE0s7Vj5dwN452S2zOp7QtghjpbSljqNPLd1s5P3tyFezj." + "'", str1, "$6$CyDhj.Ml$um69yhECTjg9Em.BvP6LRvqqWFKalIM5tWeXlddpE0s7Vj5dwN452S2zOp7QtghjpbSljqNPLd1s5P3tyFezj.");
    }

    @Test
    public void test2038() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2038");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        java.nio.ByteBuffer byteBuffer4 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest1, byteBuffer4);
        java.security.MessageDigest messageDigest6 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream7 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest6, inputStream7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream7);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(inputStream7);
        byte[] byteArray14 = org.apache.commons.codec.digest.DigestUtils.sha512("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        org.apache.commons.codec.binary.Base32 base32_16 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet17 = null;
        byte[] byteArray19 = new byte[] { (byte) 100 };
        byte[] byteArray20 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet17, byteArray19);
        byte[] byteArray21 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray20);
        boolean boolean23 = base32_16.isInAlphabet(byteArray21, false);
        org.apache.commons.codec.CodecPolicy codecPolicy24 = base32_16.getCodecPolicy();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream25 = new org.apache.commons.codec.binary.Base32InputStream(inputStream7, false, (-965378730), byteArray14, codecPolicy24);
        java.security.MessageDigest messageDigest26 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, (java.io.InputStream) base32InputStream25);
        java.io.File file27 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray28 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest1, file27);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteBuffer4);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[-99, -100, 49, -97, 2, -122, 80, -111, -15, 37, 12, 117, -65, 27, -89, 78, 99, -88, 116, -118, -52, 81, 70, 55, 112, -19, 51, -79, 52, -22, -103, -31, -100, -50, 83, 84, -24, -52, -24, -5, 46, -124, -89, 47, -93, 90, 18, 13]");
        org.junit.Assert.assertNotNull(messageDigest6);
        org.junit.Assert.assertEquals(messageDigest6.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream7);
        org.junit.Assert.assertNotNull(messageDigest8);
        org.junit.Assert.assertEquals(messageDigest8.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str9, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str10, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[-23, -79, 11, -33, -89, -101, -39, -8, -117, -105, -106, -5, -21, -106, 50, -56, 21, 18, -61, -114, 105, 80, -19, -101, 10, -56, -40, -85, 92, -106, -81, -9, -50, -69, 98, -2, -85, -107, -112, -42, -17, -116, -95, 49, -86, 28, 11, -23, -119, -50, -86, -49, 59, 89, 81, 51, -52, -123, 46, -91, -69, 38, -16, -69]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[100]");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[100]");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean23 + "' != '" + false + "'", boolean23 == false);
        org.junit.Assert.assertTrue("'" + codecPolicy24 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy24.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(messageDigest26);
        org.junit.Assert.assertEquals(messageDigest26.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test2039() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2039");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.lang.String str15 = quotedPrintableCodec1.getDefaultCharset();
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec18 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray24 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str25 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray24);
        java.lang.String str27 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray24, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str28 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray24);
        java.lang.String str29 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray24);
        java.lang.String str30 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray24);
        java.lang.Object obj31 = quotedPrintableCodec18.decode((java.lang.Object) byteArray24);
        java.lang.String str32 = quotedPrintableCodec18.getDefaultCharset();
        java.lang.String str33 = quotedPrintableCodec18.getDefaultCharset();
        java.lang.String str35 = quotedPrintableCodec18.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.nio.charset.Charset charset37 = org.apache.commons.codec.Charsets.UTF_16BE;
        java.lang.String str38 = quotedPrintableCodec18.encode("00001010000011010110100001000001010100010110000101000001011001110100011101000001", charset37);
        java.lang.String str39 = quotedPrintableCodec1.decode("$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/", charset37);
        java.lang.String str41 = quotedPrintableCodec1.decode("$1$R3.5of0S$M7WoGc.xSqd9c0i/foPQj.");
        java.lang.Object obj43 = quotedPrintableCodec1.decode((java.lang.Object) "964b3fb343f00f2d7b965c70cac0d28238933498e402d8b42dc7cd7adc56d5c7");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str8, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str10, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "AAAAAAA" + "'", str11, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str12, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str13, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "UTF-8" + "'", str15, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str25, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str27, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str28 + "' != '" + "AAAAAAA" + "'", str28, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str29, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str30, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj31);
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "UTF-8" + "'", str32, "UTF-8");
        org.junit.Assert.assertEquals("'" + str33 + "' != '" + "UTF-8" + "'", str33, "UTF-8");
        org.junit.Assert.assertEquals("'" + str35 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str35, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(charset37);
        org.junit.Assert.assertEquals("'" + str38 + "' != '" + "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001" + "'", str38, "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001");
        org.junit.Assert.assertEquals("'" + str39 + "' != '" + "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd" + "'", str39, "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd");
        org.junit.Assert.assertEquals("'" + str41 + "' != '" + "$1$R3.5of0S$M7WoGc.xSqd9c0i/foPQj." + "'", str41, "$1$R3.5of0S$M7WoGc.xSqd9c0i/foPQj.");
        org.junit.Assert.assertEquals("'" + obj43 + "' != '" + "964b3fb343f00f2d7b965c70cac0d28238933498e402d8b42dc7cd7adc56d5c7" + "'", obj43, "964b3fb343f00f2d7b965c70cac0d28238933498e402d8b42dc7cd7adc56d5c7");
    }

    @Test
    public void test2040() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2040");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf8("$6$mPBymwvz$8BKX7YMYJAopwDuhFXw.J4bVHToRmmRv2ZPqdUe.IDI.REiA6Zxa6PCgO4BuDb4VkPIP8SHsZVpUZoZ2w/AZn0");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[36, 54, 36, 109, 80, 66, 121, 109, 119, 118, 122, 36, 56, 66, 75, 88, 55, 89, 77, 89, 74, 65, 111, 112, 119, 68, 117, 104, 70, 88, 119, 46, 74, 52, 98, 86, 72, 84, 111, 82, 109, 109, 82, 118, 50, 90, 80, 113, 100, 85, 101, 46, 73, 68, 73, 46, 82, 69, 105, 65, 54, 90, 120, 97, 54, 80, 67, 103, 79, 52, 66, 117, 68, 98, 52, 86, 107, 80, 73, 80, 56, 83, 72, 115, 90, 86, 112, 85, 90, 111, 90, 50, 119, 47, 65, 90, 110, 48]");
    }

    @Test
    public void test2041() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2041");
        org.apache.commons.codec.binary.Base16 base16_0 = new org.apache.commons.codec.binary.Base16();
        boolean boolean2 = base16_0.isInAlphabet("AAAAAAA");
        byte[] byteArray6 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray6, true);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray6);
        boolean boolean11 = base16_0.isInAlphabet(byteArray6, true);
        java.security.MessageDigest messageDigest12 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream13 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest14 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest12, inputStream13);
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream13);
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream13);
        byte[] byteArray18 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray19 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray18);
        java.io.InputStream inputStream20 = java.io.InputStream.nullInputStream();
        java.lang.String str21 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray19, inputStream20);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(inputStream20);
        byte[] byteArray23 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray16, inputStream20);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj24 = base16_0.decode((java.lang.Object) byteArray16);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid octet in encoded value: -80");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + true + "'", boolean2 == true);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "ffffff" + "'", str8, "ffffff");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str9, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean11 + "' != '" + false + "'", boolean11 == false);
        org.junit.Assert.assertNotNull(messageDigest12);
        org.junit.Assert.assertEquals(messageDigest12.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream13);
        org.junit.Assert.assertNotNull(messageDigest14);
        org.junit.Assert.assertEquals(messageDigest14.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str15, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream20);
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str21, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" + "'", str22, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[24, -9, 96, -66, 48, -95, 61, 42, 79, -23, -106, -65, 91, 112, -88, -79, -109, 89, 79, -16, 55, -111, 109, -68, 55, -73, -115, -32, 12, 14, -56, -52, 47, -70, -109, 106, 107, 114, 82, 106, 115, 121, -120, -10, 5, -93, 48, -128]");
    }

    @Test
    public void test2042() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2042");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha1Digest();
        byte[] byteArray3 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray4 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray3);
        java.io.InputStream inputStream5 = java.io.InputStream.nullInputStream();
        java.lang.String str6 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray4, inputStream5);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream7 = new org.apache.commons.codec.binary.Base64InputStream(inputStream5);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream7);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha256Hex((java.io.InputStream) base64InputStream7);
        byte[] byteArray14 = org.apache.commons.codec.digest.DigestUtils.sha3_224("SHA3-256");
        java.lang.String str15 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray14);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.md2Hex(byteArray14);
        java.nio.charset.Charset charset18 = org.apache.commons.codec.Charsets.UTF_16;
        org.apache.commons.codec.binary.Base64 base64_20 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy21 = base64_20.getCodecPolicy();
        org.apache.commons.codec.net.BCodec bCodec22 = new org.apache.commons.codec.net.BCodec(charset18, codecPolicy21);
        org.apache.commons.codec.binary.Base16 base16_23 = new org.apache.commons.codec.binary.Base16(false, codecPolicy21);
        org.apache.commons.codec.binary.Base32InputStream base32InputStream24 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base64InputStream7, true, 0, byteArray14, codecPolicy21);
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest1, (java.io.InputStream) base64InputStream7);
        org.apache.commons.codec.binary.Base64 base64_30 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy31 = base64_30.getCodecPolicy();
        org.apache.commons.codec.binary.Base16 base16_32 = new org.apache.commons.codec.binary.Base16(true, codecPolicy31);
        org.apache.commons.codec.binary.Base16 base16_33 = new org.apache.commons.codec.binary.Base16(true, codecPolicy31);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_34 = new org.apache.commons.codec.binary.Base64((-1534769883), byteArray25, false, codecPolicy31);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [?9??^kK?2U??`??????]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-1 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str6, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str8, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str9, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str10, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
// flaky:         org.junit.Assert.assertEquals("'" + str15 + "' != '" + "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" + "'", str15, "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "a9c412bc47e545109e63db091b6ee4b3" + "'", str16, "a9c412bc47e545109e63db091b6ee4b3");
        org.junit.Assert.assertNotNull(charset18);
        org.junit.Assert.assertTrue("'" + codecPolicy21 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy21.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[-38, 57, -93, -18, 94, 107, 75, 13, 50, 85, -65, -17, -107, 96, 24, -112, -81, -40, 7, 9]");
        org.junit.Assert.assertTrue("'" + codecPolicy31 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy31.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test2043() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2043");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        java.nio.charset.Charset charset4 = qCodec3.getCharset();
        java.nio.charset.Charset charset5 = qCodec3.getCharset();
        java.lang.Object obj6 = null;
        java.lang.Object obj7 = qCodec3.encode(obj6);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec10 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        java.lang.String str19 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray16, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str20 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray16);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray16);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray16);
        java.lang.Object obj23 = quotedPrintableCodec10.decode((java.lang.Object) byteArray16);
        java.lang.String str24 = quotedPrintableCodec10.getDefaultCharset();
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec27 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray33 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str34 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray33);
        java.lang.String str36 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray33, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str37 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray33);
        java.lang.String str38 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray33);
        java.lang.String str39 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray33);
        java.lang.Object obj40 = quotedPrintableCodec27.decode((java.lang.Object) byteArray33);
        java.lang.String str41 = quotedPrintableCodec27.getDefaultCharset();
        java.lang.String str42 = quotedPrintableCodec27.getDefaultCharset();
        java.lang.String str44 = quotedPrintableCodec27.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.nio.charset.Charset charset46 = org.apache.commons.codec.Charsets.UTF_16BE;
        java.lang.String str47 = quotedPrintableCodec27.encode("00001010000011010110100001000001010100010110000101000001011001110100011101000001", charset46);
        java.lang.String str48 = quotedPrintableCodec10.decode("$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/", charset46);
        java.lang.String str49 = qCodec3.encode("$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30", charset46);
        java.nio.charset.Charset charset50 = qCodec3.getCharset();
        boolean boolean51 = qCodec3.isEncodeBlanks();
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset4);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertNull(obj7);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str19, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "AAAAAAA" + "'", str20, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str21, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str22, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj23);
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "UTF-8" + "'", str24, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str34, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str36, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str37 + "' != '" + "AAAAAAA" + "'", str37, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str38 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str38, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str39 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str39, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj40);
        org.junit.Assert.assertEquals("'" + str41 + "' != '" + "UTF-8" + "'", str41, "UTF-8");
        org.junit.Assert.assertEquals("'" + str42 + "' != '" + "UTF-8" + "'", str42, "UTF-8");
        org.junit.Assert.assertEquals("'" + str44 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str44, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(charset46);
        org.junit.Assert.assertEquals("'" + str47 + "' != '" + "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001" + "'", str47, "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001");
        org.junit.Assert.assertEquals("'" + str48 + "' != '" + "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd" + "'", str48, "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd");
        org.junit.Assert.assertEquals("'" + str49 + "' != '" + "=?UTF-16BE?Q?=00$=006=00$=00o=00l=00h=00A=00U=00V=00h=000=00$=00f=00d=002=00x=00F=00X=00N=00N=00K=00W=00O=00X=003=00f=00O=00Q=00Q=00k=00K=00u=001=00d=00E=00D=00I=007=00A=00b=00q=00o=00o=00F=00E=00N=00R=008=00N=00K=00m=00z=00v=00t=00.=00X=00I=00d=00W=00U=00U=00e=00d=00S=00G=007=00/=00q=00x=00n=003=00D=00c=00l=00g=004=00n=00o=00x=000=00C=00e=00F=00S=00D=00y=00F=00w=009=00A=00e=00y=009=00W=00M=00N=003=000?=" + "'", str49, "=?UTF-16BE?Q?=00$=006=00$=00o=00l=00h=00A=00U=00V=00h=000=00$=00f=00d=002=00x=00F=00X=00N=00N=00K=00W=00O=00X=003=00f=00O=00Q=00Q=00k=00K=00u=001=00d=00E=00D=00I=007=00A=00b=00q=00o=00o=00F=00E=00N=00R=008=00N=00K=00m=00z=00v=00t=00.=00X=00I=00d=00W=00U=00U=00e=00d=00S=00G=007=00/=00q=00x=00n=003=00D=00c=00l=00g=004=00n=00o=00x=000=00C=00e=00F=00S=00D=00y=00F=00w=009=00A=00e=00y=009=00W=00M=00N=003=000?=");
        org.junit.Assert.assertNotNull(charset50);
        org.junit.Assert.assertTrue("'" + boolean51 + "' != '" + false + "'", boolean51 == false);
    }

    @Test
    public void test2044() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2044");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec14 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet15 = null;
        byte[] byteArray17 = new byte[] { (byte) 100 };
        byte[] byteArray18 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet15, byteArray17);
        byte[] byteArray19 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray18);
        byte[] byteArray20 = uRLCodec14.encode(byteArray19);
        java.lang.String str21 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray5, byteArray19);
        byte[] byteArray22 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray5);
        java.io.InputStream inputStream23 = java.io.InputStream.nullInputStream();
        java.lang.String str24 = org.apache.commons.codec.digest.DigestUtils.md5Hex(inputStream23);
        byte[] byteArray25 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray5, inputStream23);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream27 = new org.apache.commons.codec.binary.Base64InputStream(inputStream23, true);
        // The following exception was thrown during execution in test generation
        try {
            long long29 = base64InputStream27.skip((-3032679231428807052L));
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Negative skip length: -3032679231428807052");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[100]");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[100]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str21, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(inputStream23);
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "d41d8cd98f00b204e9800998ecf8427e" + "'", str24, "d41d8cd98f00b204e9800998ecf8427e");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[-74, 19, 103, -102, 8, 20, -39, -20, 119, 47, -107, -41, 120, -61, 95, -59, -1, 22, -105, -60, -109, 113, 86, 83, -58, -57, 18, 20, 66, -110, -59, -83]");
    }

    @Test
    public void test2045() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2045");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream4 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream0, (org.apache.commons.codec.binary.BaseNCodec) base16_2, false);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream6 = new org.apache.commons.codec.binary.Base32OutputStream(outputStream0, true);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream7 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base32OutputStream6);
        org.junit.Assert.assertNotNull(outputStream0);
    }

    @Test
    public void test2046() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2046");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf8("ca73f0c17889db16a65cc87b97ac0bcd537d3f9d");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[99, 97, 55, 51, 102, 48, 99, 49, 55, 56, 56, 57, 100, 98, 49, 54, 97, 54, 53, 99, 99, 56, 55, 98, 57, 55, 97, 99, 48, 98, 99, 100, 53, 51, 55, 100, 51, 102, 57, 100]");
    }

    @Test
    public void test2047() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2047");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(false);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_224("1nualuGt.TbmU");
        byte[] byteArray4 = quotedPrintableCodec1.decode(byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray4);
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[110, 88, 101, 107, 95, 95, 56, 95, 53, 120, 107, 122, 121, 95, 51, 102, 66, 79, 75, 117, 101, 117, 115, 54, 65, 48, 117, 68, 78, 84, 122, 69, 122, 74, 86, 105, 75, 65]");
// flaky:         org.junit.Assert.assertEquals("'" + str6 + "' != '" + "$5$4Y5ZaY5v$4rIft6DLQShmMjrbpqELUw/BWKNCSf.y.kmW7vb6aF3" + "'", str6, "$5$4Y5ZaY5v$4rIft6DLQShmMjrbpqELUw/BWKNCSf.y.kmW7vb6aF3");
    }

    @Test
    public void test2048() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2048");
        org.apache.commons.codec.language.Metaphone metaphone0 = new org.apache.commons.codec.language.Metaphone();
        java.lang.String str2 = metaphone0.encode("9b9e60058fae476c9ee6ef8fc698d89e");
        java.lang.String str4 = metaphone0.metaphone("1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
        java.lang.Object obj6 = metaphone0.encode((java.lang.Object) "Ae3f");
        java.lang.String str8 = metaphone0.encode("Ae3f");
        java.lang.String str10 = metaphone0.metaphone("");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "BFKF" + "'", str2, "BFKF");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "BTFT" + "'", str4, "BTFT");
        org.junit.Assert.assertEquals("'" + obj6 + "' != '" + "EF" + "'", obj6, "EF");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "EF" + "'", str8, "EF");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "" + "'", str10, "");
    }

    @Test
    public void test2049() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2049");
        org.apache.commons.codec.binary.Base64 base64_1 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy2 = base64_1.getCodecPolicy();
        byte[] byteArray4 = base64_1.decode("fad2595114e5c45a896f3481bb63e7097f9f106fd3591c1e37c30fee");
        org.junit.Assert.assertTrue("'" + codecPolicy2 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy2.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[125, -89, 118, -25, -34, 117, -41, -121, -71, 115, -114, 90, -13, -34, -97, -33, -113, 53, 109, -66, -73, 123, -67, 61, -19, -1, 95, -41, 78, -97, 119, 126, 125, -43, -51, 94, -33, -73, 55, -47, -9, -98]");
    }

    @Test
    public void test2050() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2050");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        qCodec3.setEncodeBlanks(true);
        java.lang.String str7 = qCodec3.encode("\000\000\000\000\000");
        java.nio.charset.Charset charset9 = org.apache.commons.codec.Charsets.UTF_16LE;
        java.lang.String str10 = qCodec3.encode("\000\ufffd", charset9);
        java.nio.charset.Charset charset12 = org.apache.commons.codec.Charsets.UTF_8;
        java.lang.String str13 = qCodec3.encode("1dafb4883502066a147fb8a7fabf1856", charset12);
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "=?UTF-8?Q?=00=00=00=00=00?=" + "'", str7, "=?UTF-8?Q?=00=00=00=00=00?=");
        org.junit.Assert.assertNotNull(charset9);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "=?UTF-16LE?Q?=00=00=FD=FF?=" + "'", str10, "=?UTF-16LE?Q?=00=00=FD=FF?=");
        org.junit.Assert.assertNotNull(charset12);
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "=?UTF-8?Q?1dafb4883502066a147fb8a7fabf1856?=" + "'", str13, "=?UTF-8?Q?1dafb4883502066a147fb8a7fabf1856?=");
    }

    @Test
    public void test2051() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2051");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.lang.String str3 = bCodec2.getDefaultCharset();
        boolean boolean4 = bCodec2.isStrictDecoding();
        boolean boolean5 = bCodec2.isStrictDecoding();
        java.io.InputStream inputStream6 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream7 = new org.apache.commons.codec.binary.Base16InputStream(inputStream6);
        java.lang.Object obj8 = bCodec2.decode((java.lang.Object) inputStream6);
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "UTF-8" + "'", str3, "UTF-8");
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
        org.junit.Assert.assertTrue("'" + boolean5 + "' != '" + false + "'", boolean5 == false);
        org.junit.Assert.assertNull(obj8);
    }

    @Test
    public void test2052() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2052");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        org.apache.commons.codec.language.bm.Lang lang6 = phoneticEngine4.getLang();
        int int7 = phoneticEngine4.getMaxPhonemes();
        int int8 = phoneticEngine4.getMaxPhonemes();
        org.apache.commons.codec.language.bm.NameType nameType10 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder11 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType12 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder11.setRuleType(ruleType12);
        org.apache.commons.codec.language.bm.NameType nameType14 = beiderMorseEncoder11.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType15 = beiderMorseEncoder11.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet16 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap17 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType10, ruleType15, languageSet16);
        boolean boolean18 = languageSet16.isEmpty();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str19 = phoneticEngine4.encode("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", languageSet16);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(ruleType5);
        org.junit.Assert.assertNull(lang6);
        org.junit.Assert.assertTrue("'" + int7 + "' != '" + (-1) + "'", int7 == (-1));
        org.junit.Assert.assertTrue("'" + int8 + "' != '" + (-1) + "'", int8 == (-1));
        org.junit.Assert.assertTrue("'" + nameType10 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType10.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType12 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType12.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType14 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType14.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType15 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType15.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet16);
        org.junit.Assert.assertNotNull(strMap17);
        org.junit.Assert.assertTrue("'" + boolean18 + "' != '" + true + "'", boolean18 == true);
    }

    @Test
    public void test2053() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2053");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        boolean boolean3 = doubleMetaphone0.isDoubleMetaphoneEqual("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "7664fbe062101db016383ccc7d71037a073342cb0a161828f86315b6b9b06ed4053486c8d4f60dd3eb5eefa806facff24d12a98529fe15a02e986cca332ce518");
        java.lang.String str5 = doubleMetaphone0.doubleMetaphone("ash");
        org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult7 = doubleMetaphone0.new DoubleMetaphoneResult((int) (short) 100);
        boolean boolean10 = doubleMetaphone0.isDoubleMetaphoneEqual("18f760be30a13d2a4fe996bf5b70a8b193594ff037916dbc37b78de00c0ec8cc2fba936a6b72526a737988f605a33080", "1a8b0c056a68adf6aa082a0a1251c0d77c7f2519a27d869b0c6a134243fa2b6dc0acbaca33b153b0ae7190e7b53f0a4b4e7f211628e25f39a8c9a6a737d1caa7");
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "AX" + "'", str5, "AX");
        org.junit.Assert.assertTrue("'" + boolean10 + "' != '" + false + "'", boolean10 == false);
    }

    @Test
    public void test2054() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2054");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        byte[] byteArray8 = uRLCodec1.decode(byteArray5);
        byte[] byteArray9 = null;
        byte[] byteArray10 = uRLCodec1.decode(byteArray9);
        java.lang.String str11 = uRLCodec1.getDefaultCharset();
        java.util.BitSet bitSet12 = null;
        byte[] byteArray14 = new byte[] { (byte) 100 };
        byte[] byteArray15 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet12, byteArray14);
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray15);
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.md2Hex(byteArray15);
        byte[] byteArray18 = uRLCodec1.encode(byteArray15);
        java.lang.String str21 = uRLCodec1.encode("", "ISO-8859-1");
        java.util.BitSet bitSet22 = null;
        byte[] byteArray24 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray24);
        byte[] byteArray27 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet22, byteArray25, false);
        byte[] byteArray28 = uRLCodec1.encode(byteArray25);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str7, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
        org.junit.Assert.assertNull(byteArray10);
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "hi!" + "'", str11, "hi!");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[100]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[100]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "96978c0796ce94f7beb31576946b6bed" + "'", str17, "96978c0796ce94f7beb31576946b6bed");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[100]");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "" + "'", str21, "");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[-94, -71, -20, 113, -13, 85, 125, -85, -105, -45, 25, -6, 7, 28, -4, -54, 26, 118, -50, 96, 126, -92, 117, 32, 53, 51, -80, -85, -69, -86, 103, -30]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[61, 65, 50, 61, 66, 57, 61, 69, 67, 113, 61, 70, 51, 85, 125, 61, 65, 66, 61, 57, 55, 61, 68, 51, 61, 49, 57, 61, 70, 65, 61, 48, 55, 61, 49, 67, 61, 70, 67, 61, 67, 65, 61, 49, 65, 118, 61, 67, 69, 96, 126, 61, 65, 52, 117, 32, 53, 51, 61, 66, 48, 61, 65, 66, 61, 66, 66, 61, 65, 65, 103, 61, 69, 50]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[37, 65, 50, 37, 66, 57, 37, 69, 67, 113, 37, 70, 51, 85, 37, 55, 68, 37, 65, 66, 37, 57, 55, 37, 68, 51, 37, 49, 57, 37, 70, 65, 37, 48, 55, 37, 49, 67, 37, 70, 67, 37, 67, 65, 37, 49, 65, 118, 37, 67, 69, 37, 54, 48, 37, 55, 69, 37, 65, 52, 117, 43, 53, 51, 37, 66, 48, 37, 65, 66, 37, 66, 66, 37, 65, 65, 103, 37, 69, 50]");
    }

    @Test
    public void test2055() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2055");
        // The following exception was thrown during execution in test generation
        try {
            long long3 = org.apache.commons.codec.digest.MurmurHash2.hash64("0Ac7cg1i0oNqE", 1787795390, (int) (short) 0);
            org.junit.Assert.fail("Expected exception of type java.lang.StringIndexOutOfBoundsException; message: begin 1787795390, end 1787795390, length 13");
        } catch (java.lang.StringIndexOutOfBoundsException e) {
            // Expected exception.
        }
    }

    @Test
    public void test2056() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2056");
        org.apache.commons.codec.language.bm.Rule.PhonemeExpr phonemeExpr3 = null;
        org.apache.commons.codec.language.bm.Rule rule4 = new org.apache.commons.codec.language.bm.Rule("d7bXONth0AIyo", "ABUAA2IAEE======", "org.apache.commons.codec.DecoderException: org.apache.commons.codec.EncoderException", phonemeExpr3);
        org.apache.commons.codec.language.bm.Rule.RPattern rPattern5 = rule4.getRContext();
        java.lang.String str6 = rule4.getPattern();
        org.apache.commons.codec.language.bm.Rule.RPattern rPattern7 = rule4.getRContext();
        org.junit.Assert.assertNotNull(rPattern5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "d7bXONth0AIyo" + "'", str6, "d7bXONth0AIyo");
        org.junit.Assert.assertNotNull(rPattern7);
    }

    @Test
    public void test2057() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2057");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha384((java.io.InputStream) base64InputStream5);
        byte[] byteArray10 = base64InputStream5.readNBytes((int) ' ');
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha1Hex((java.io.InputStream) base64InputStream5);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "da39a3ee5e6b4b0d3255bfef95601890afd80709" + "'", str11, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    public void test2058() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2058");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        java.lang.String str2 = beiderMorseEncoder0.encode("d41d8cd98f00b204e9800998ecf8427e");
        java.lang.String str4 = beiderMorseEncoder0.encode("SHA3-224");
        org.apache.commons.codec.language.bm.RuleType ruleType5 = beiderMorseEncoder0.getRuleType();
        boolean boolean6 = beiderMorseEncoder0.isConcat();
        org.apache.commons.codec.language.bm.NameType nameType7 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType8 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet9 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap10 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType7, ruleType8, languageSet9);
        org.apache.commons.codec.language.bm.RuleType ruleType11 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine14 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType7, ruleType11, false, (int) ' ');
        org.apache.commons.codec.language.bm.Languages languages15 = org.apache.commons.codec.language.bm.Languages.getInstance(nameType7);
        beiderMorseEncoder0.setNameType(nameType7);
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder17 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        boolean boolean18 = beiderMorseEncoder17.isConcat();
        org.apache.commons.codec.language.bm.NameType nameType19 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang20 = org.apache.commons.codec.language.bm.Lang.instance(nameType19);
        org.apache.commons.codec.language.bm.NameType nameType21 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder22 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType23 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder22.setRuleType(ruleType23);
        org.apache.commons.codec.language.bm.NameType nameType25 = beiderMorseEncoder22.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType26 = beiderMorseEncoder22.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet27 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap28 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType21, ruleType26, languageSet27);
        org.apache.commons.codec.language.bm.NameType nameType29 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang30 = org.apache.commons.codec.language.bm.Lang.instance(nameType29);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet32 = lang30.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet34 = lang30.guessLanguages("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap35 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType19, ruleType26, languageSet34);
        org.apache.commons.codec.language.bm.RuleType ruleType36 = org.apache.commons.codec.language.bm.RuleType.APPROX;
        org.apache.commons.codec.language.bm.NameType nameType37 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang38 = org.apache.commons.codec.language.bm.Lang.instance(nameType37);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet40 = lang38.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet42 = lang38.guessLanguages("400000");
        java.lang.String str43 = languageSet42.getAny();
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap44 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType19, ruleType36, languageSet42);
        beiderMorseEncoder17.setRuleType(ruleType36);
        java.lang.String[] strArray84 = new java.lang.String[] { "ffffff", "663b90c899fa25a111067be0c22ffc64dcf581c2", "SHA-224", "0Acd8L3u4hVxI", "UTF-16LE", "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "2ef0725975afd171e9cb76444b4969c3", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "ffffff", "6IiiRyxmjcARw", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "0A01640101", "2ef0725975afd171e9cb76444b4969c3", "663b90c899fa25a111067be0c22ffc64dcf581c2", "", "ffffff", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", "6IiiRyxmjcARw", "663b90c899fa25a111067be0c22ffc64dcf581c2", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "MD2", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "99448658175a0534e08dbca1fe67b58231a53eec", "0A01640101", "0A01640101", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "SHA3-256", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107", "", "663b90c899fa25a111067be0c22ffc64dcf581c2", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" };
        java.util.LinkedHashSet<java.lang.String> strSet85 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean86 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet85, strArray84);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet87 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet85);
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap88 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType7, ruleType36, languageSet87);
        org.apache.commons.codec.language.bm.NameType nameType89 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder90 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType91 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder90.setRuleType(ruleType91);
        org.apache.commons.codec.language.bm.RuleType ruleType93 = beiderMorseEncoder90.getRuleType();
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine96 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType89, ruleType93, true, (-488200341));
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine99 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType7, ruleType93, false, 64);
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi" + "'", str2, "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "sa|so" + "'", str4, "sa|so");
        org.junit.Assert.assertTrue("'" + ruleType5 + "' != '" + org.apache.commons.codec.language.bm.RuleType.APPROX + "'", ruleType5.equals(org.apache.commons.codec.language.bm.RuleType.APPROX));
        org.junit.Assert.assertTrue("'" + boolean6 + "' != '" + true + "'", boolean6 == true);
        org.junit.Assert.assertTrue("'" + nameType7 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType7.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType8 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType8.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet9);
        org.junit.Assert.assertNotNull(strMap10);
        org.junit.Assert.assertNotNull(languages15);
        org.junit.Assert.assertTrue("'" + boolean18 + "' != '" + true + "'", boolean18 == true);
        org.junit.Assert.assertTrue("'" + nameType19 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType19.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang20);
        org.junit.Assert.assertTrue("'" + nameType21 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType21.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType23 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType23.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType25 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType25.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType26 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType26.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet27);
        org.junit.Assert.assertNotNull(strMap28);
        org.junit.Assert.assertTrue("'" + nameType29 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType29.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang30);
        org.junit.Assert.assertNotNull(languageSet32);
        org.junit.Assert.assertNotNull(languageSet34);
        org.junit.Assert.assertNotNull(strMap35);
        org.junit.Assert.assertTrue("'" + ruleType36 + "' != '" + org.apache.commons.codec.language.bm.RuleType.APPROX + "'", ruleType36.equals(org.apache.commons.codec.language.bm.RuleType.APPROX));
        org.junit.Assert.assertTrue("'" + nameType37 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType37.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang38);
        org.junit.Assert.assertNotNull(languageSet40);
        org.junit.Assert.assertNotNull(languageSet42);
        org.junit.Assert.assertEquals("'" + str43 + "' != '" + "greek" + "'", str43, "greek");
        org.junit.Assert.assertNotNull(strMap44);
        org.junit.Assert.assertNotNull(strArray84);
        org.junit.Assert.assertTrue("'" + boolean86 + "' != '" + true + "'", boolean86 == true);
        org.junit.Assert.assertNotNull(languageSet87);
        org.junit.Assert.assertNotNull(strMap88);
        org.junit.Assert.assertTrue("'" + nameType89 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType89.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType91 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType91.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + ruleType93 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType93.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
    }

    @Test
    public void test2059() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2059");
        java.lang.String[] strArray38 = new java.lang.String[] { "ffffff", "663b90c899fa25a111067be0c22ffc64dcf581c2", "SHA-224", "0Acd8L3u4hVxI", "UTF-16LE", "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "2ef0725975afd171e9cb76444b4969c3", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "ffffff", "6IiiRyxmjcARw", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "0A01640101", "2ef0725975afd171e9cb76444b4969c3", "663b90c899fa25a111067be0c22ffc64dcf581c2", "", "ffffff", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", "6IiiRyxmjcARw", "663b90c899fa25a111067be0c22ffc64dcf581c2", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "MD2", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "99448658175a0534e08dbca1fe67b58231a53eec", "0A01640101", "0A01640101", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "SHA3-256", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107", "", "663b90c899fa25a111067be0c22ffc64dcf581c2", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" };
        java.util.LinkedHashSet<java.lang.String> strSet39 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean40 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet39, strArray38);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet41 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet39);
        boolean boolean42 = languageSet41.isSingleton();
        org.apache.commons.codec.language.bm.NameType nameType43 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang44 = org.apache.commons.codec.language.bm.Lang.instance(nameType43);
        org.apache.commons.codec.language.bm.Languages languages45 = org.apache.commons.codec.language.bm.Languages.getInstance(nameType43);
        org.apache.commons.codec.language.bm.RuleType ruleType46 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.NameType nameType47 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang48 = org.apache.commons.codec.language.bm.Lang.instance(nameType47);
        org.apache.commons.codec.language.bm.NameType nameType49 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder50 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType51 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder50.setRuleType(ruleType51);
        org.apache.commons.codec.language.bm.NameType nameType53 = beiderMorseEncoder50.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType54 = beiderMorseEncoder50.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet55 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap56 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType49, ruleType54, languageSet55);
        org.apache.commons.codec.language.bm.NameType nameType57 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang58 = org.apache.commons.codec.language.bm.Lang.instance(nameType57);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet60 = lang58.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet62 = lang58.guessLanguages("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap63 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType47, ruleType54, languageSet62);
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap64 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType43, ruleType46, languageSet62);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet65 = languageSet41.restrictTo(languageSet62);
        boolean boolean67 = languageSet62.contains("779a9a01aaac1e6d39fd1edd3ad7c11d");
        org.junit.Assert.assertNotNull(strArray38);
        org.junit.Assert.assertTrue("'" + boolean40 + "' != '" + true + "'", boolean40 == true);
        org.junit.Assert.assertNotNull(languageSet41);
        org.junit.Assert.assertTrue("'" + boolean42 + "' != '" + false + "'", boolean42 == false);
        org.junit.Assert.assertTrue("'" + nameType43 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType43.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang44);
        org.junit.Assert.assertNotNull(languages45);
        org.junit.Assert.assertTrue("'" + ruleType46 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType46.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertTrue("'" + nameType47 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType47.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang48);
        org.junit.Assert.assertTrue("'" + nameType49 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType49.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType51 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType51.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType53 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType53.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType54 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType54.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet55);
        org.junit.Assert.assertNotNull(strMap56);
        org.junit.Assert.assertTrue("'" + nameType57 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType57.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang58);
        org.junit.Assert.assertNotNull(languageSet60);
        org.junit.Assert.assertNotNull(languageSet62);
        org.junit.Assert.assertNotNull(strMap63);
        org.junit.Assert.assertNotNull(strMap64);
        org.junit.Assert.assertNotNull(languageSet65);
        org.junit.Assert.assertTrue("'" + boolean67 + "' != '" + false + "'", boolean67 == false);
    }

    @Test
    public void test2060() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2060");
        org.apache.commons.codec.EncoderException encoderException1 = new org.apache.commons.codec.EncoderException("BFKF");
    }

    @Test
    public void test2061() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2061");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex("AAAAAAA=", "$6$z69expz7$sOVlycqle/TbrroHMLe6Ezodc9LcXsTit5JcMvZtfLcBjMULYHVyPSo1LY.otAbAyAfFbBzBTim3F.ja41N4x1");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "23d6d3aa805f10fc319f4cec6f6f91aaa830391eb015eea6d323d53788c9f38be10b9b556aa71deea6128fcf8e5608efa7abc0f771bf720cfa20f451995738a0" + "'", str2, "23d6d3aa805f10fc319f4cec6f6f91aaa830391eb015eea6d323d53788c9f38be10b9b556aa71deea6128fcf8e5608efa7abc0f771bf720cfa20f451995738a0");
    }

    @Test
    public void test2062() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2062");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        java.lang.String str9 = bCodec2.encode("\u1d74\u5560\u9deb\u2399\ue3a9\ue89d\uf686\uef20\u8b69\u2d45\ube17\ud2e2\u8c21\ufffd\u8d2e");
        byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.sha512_256("");
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray11);
        int int16 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray12, (int) (byte) 0, (-2042891860), 0);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj17 = bCodec2.decode((java.lang.Object) 0);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type java.lang.Integer cannot be decoded using BCodec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "=?UTF-8?B?4bW05ZWg6ber4o6Z7o6p7qKd75qG7ryg6K2p4rWF67iX7Yui6LCh77+96LSu?=" + "'", str9, "=?UTF-8?B?4bW05ZWg6ber4o6Z7o6p7qKd75qG7ryg6K2p4rWF67iX7Yui6LCh77+96LSu?=");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[-58, 114, -72, -47, -17, 86, -19, 40, -85, -121, -61, 98, 44, 81, 20, 6, -101, -35, 58, -41, -72, -7, 115, 116, -104, -48, -64, 30, -50, -16, -106, 122]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[32, -39, 31, 96, 101, 120, 98, 8, 87, 108, -31, 27, -25, -104, 91, 41, -2, 73, 60, -32, -6, 38, 39, 78, -25, 113, -31, -42, -88, 16, 47, 41]");
        org.junit.Assert.assertTrue("'" + int16 + "' != '" + 1595328082 + "'", int16 == 1595328082);
    }

    @Test
    public void test2063() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2063");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        java.lang.String str4 = qCodec3.getDefaultCharset();
        java.nio.charset.Charset charset5 = qCodec3.getCharset();
        java.util.BitSet bitSet6 = null;
        byte[] byteArray8 = new byte[] { (byte) 100 };
        byte[] byteArray9 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet6, byteArray8);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray9);
        java.nio.charset.Charset charset11 = org.apache.commons.codec.Charsets.UTF_16BE;
        org.apache.commons.codec.net.QCodec qCodec12 = new org.apache.commons.codec.net.QCodec(charset11);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator13 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) qCodec12);
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder14 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        java.lang.String str16 = beiderMorseEncoder14.encode("d41d8cd98f00b204e9800998ecf8427e");
        java.lang.String str18 = beiderMorseEncoder14.encode("SHA3-224");
        java.util.BitSet bitSet19 = null;
        byte[] byteArray21 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray22 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet19, byteArray21);
        int int23 = stringEncoderComparator13.compare((java.lang.Object) str18, (java.lang.Object) byteArray22);
        byte[] byteArray24 = org.apache.commons.codec.digest.HmacUtils.hmacSha1(byteArray9, byteArray22);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj25 = qCodec3.encode((java.lang.Object) byteArray9);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type [B cannot be encoded using Q codec");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "UTF-8" + "'", str4, "UTF-8");
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0]");
// flaky:         org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$aqKk4a6N$zNm0sVBUgSa2A.Tu8SDZX/" + "'", str10, "$apr1$aqKk4a6N$zNm0sVBUgSa2A.Tu8SDZX/");
        org.junit.Assert.assertNotNull(charset11);
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi" + "'", str16, "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "sa|so" + "'", str18, "sa|so");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[]");
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[]");
        org.junit.Assert.assertTrue("'" + int23 + "' != '" + 0 + "'", int23 == 0);
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[-5, -37, 29, 27, 24, -86, 108, 8, 50, 75, 125, 100, -73, 31, -73, 99, 112, 105, 14, 29]");
    }

    @Test
    public void test2064() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2064");
        org.apache.commons.codec.language.Metaphone metaphone0 = new org.apache.commons.codec.language.Metaphone();
        java.lang.String str2 = metaphone0.encode("9b9e60058fae476c9ee6ef8fc698d89e");
        java.lang.String str4 = metaphone0.metaphone("1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
        java.lang.String str6 = metaphone0.metaphone("7cd9ea3a777159f190a5ad95fc94b919752c42564de2cb38d90df348ae98b10fe2c11be569eb8a585b7789dc83cefab4");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "BFKF" + "'", str2, "BFKF");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "BTFT" + "'", str4, "BTFT");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "KTFT" + "'", str6, "KTFT");
    }

    @Test
    public void test2065() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2065");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha1("\000");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[91, -87, 60, -99, -80, -49, -7, 63, 82, -75, 33, -41, 66, 14, 67, -10, -19, -94, 120, 79]");
    }

    @Test
    public void test2066() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2066");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet3 = lang1.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet5 = lang1.guessLanguages("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        org.apache.commons.codec.language.bm.NameType nameType6 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder7 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType8 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder7.setRuleType(ruleType8);
        org.apache.commons.codec.language.bm.NameType nameType10 = beiderMorseEncoder7.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType11 = beiderMorseEncoder7.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet12 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap13 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType6, ruleType11, languageSet12);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet14 = languageSet5.restrictTo(languageSet12);
        boolean boolean16 = languageSet14.contains("A08");
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertNotNull(languageSet3);
        org.junit.Assert.assertNotNull(languageSet5);
        org.junit.Assert.assertTrue("'" + nameType6 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType6.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType8 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType8.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType10 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType10.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType11 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType11.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet12);
        org.junit.Assert.assertNotNull(strMap13);
        org.junit.Assert.assertNotNull(languageSet14);
        org.junit.Assert.assertTrue("'" + boolean16 + "' != '" + false + "'", boolean16 == false);
    }

    @Test
    public void test2067() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2067");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray8, false);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, byteArray8);
        byte[] byteArray14 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray15 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray14);
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        java.lang.String str17 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray15, inputStream16);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream18 = new org.apache.commons.codec.binary.Base64InputStream(inputStream16);
        byte[] byteArray19 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray8, (java.io.InputStream) base64InputStream18);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex((java.io.InputStream) base64InputStream18);
        long long22 = base64InputStream18.skip((long) 64);
        base64InputStream18.mark(1787795390);
        boolean boolean25 = base64InputStream18.isStrictDecoding();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream27 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base64InputStream18, false);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream30 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base64InputStream18, true, false);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0A01640101" + "'", str11, "0A01640101");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str12, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str17, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[2, 34, -90, -86, 24, -114, 46, 116, -89, 122, -11, -103, 109, 29, -113, 57, -115, -50, -121, -67, 99, -35, 44, 88, -108, 52, 45, 68, -1, -123, 62, -43, 37, -26, -55, -24, 47, -94, 118, -68, 91, -39, 125, -89, 38, -102, -107, 112]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" + "'", str20, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        org.junit.Assert.assertTrue("'" + long22 + "' != '" + 0L + "'", long22 == 0L);
        org.junit.Assert.assertTrue("'" + boolean25 + "' != '" + false + "'", boolean25 == false);
    }

    @Test
    public void test2068() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2068");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_256("");
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray2);
        char[] charArray4 = org.apache.commons.codec.binary.Hex.encodeHex(byteArray2);
        byte[] byteArray5 = org.apache.commons.codec.binary.BinaryCodec.fromAscii(charArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray5);
        java.security.MessageDigest messageDigest7 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteArray6);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-58, 114, -72, -47, -17, 86, -19, 40, -85, -121, -61, 98, 44, 81, 20, 6, -101, -35, 58, -41, -72, -7, 115, 116, -104, -48, -64, 30, -50, -16, -106, 122]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[32, -39, 31, 96, 101, 120, 98, 8, 87, 108, -31, 27, -25, -104, 91, 41, -2, 73, 60, -32, -6, 38, 39, 78, -25, 113, -31, -42, -88, 16, 47, 41]");
        org.junit.Assert.assertNotNull(charArray4);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray4), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray4), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray4), "[c, 6, 7, 2, b, 8, d, 1, e, f, 5, 6, e, d, 2, 8, a, b, 8, 7, c, 3, 6, 2, 2, c, 5, 1, 1, 4, 0, 6, 9, b, d, d, 3, a, d, 7, b, 8, f, 9, 7, 3, 7, 4, 9, 8, d, 0, c, 0, 1, e, c, e, f, 0, 9, 6, 7, a]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 2, 0, 0, 24, 0, 0, 1]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[1, -114, 101, 58, 114, 28, -116, 34, 89, -93, -123, 65, -34, 2, -6, -60, -36, 20, -13, 92, 11, 90, 42, -21, 26, 6, 57, 28]");
        org.junit.Assert.assertNotNull(messageDigest7);
        org.junit.Assert.assertEquals(messageDigest7.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test2069() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2069");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md2("c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a");
        java.lang.String str4 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray1, "kabevdegdZafkebbeadZadpfbbdetf|kabevdegdZafkebbeakadpfbbdetf|kabevdegdZavdZebbeadZadpfbbdetf|kabevdegdZavdZebbeakadpfbbdetf|kabevdekafkebbajakadpfbbdetf|kabevdekafkebbeadZadpfbbdetf|kabevdekafkebbeakadpfbbdetf|kabevdekafkebbeatsadpfbbdetf|kabevdekafkebbiakadpfbbdetf|kabevdekaftsebbeakadpfbbdetf|kabevdekaftsebbeatsadpfbbdetf|kabevdekavdZebbeadZadpfbbdetf|kabevdekavdZebbeakadpfbbdetf|kabevdektsafkebbeakadpfbbdetf|kabevdektsafkebbeatsadpfbbdetf|kabevdektsaftsebbeakadpfbbdetf|kabevdektsaftsebbeatsadpfbbdetf|kabevdetskafkebbeakadpfbbdetf|kabevdetskafkebbeatsadpfbbdetf|kabevdetskaftsebbeakadpfbbdetf", "");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "kabevdeg$WUP595BMZrBP0wDPME.Wy0" + "'", str4, "kabevdeg$WUP595BMZrBP0wDPME.Wy0");
    }

    @Test
    public void test2070() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2070");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic0 = new org.apache.commons.codec.language.ColognePhonetic();
        java.lang.String str2 = colognePhonetic0.colognePhonetic("079564");
        boolean boolean5 = colognePhonetic0.isEncodeEqual("e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98", "08cbbefd7b26d3154a21bc6e1b5321a8c22c830337e001d4268209436634ecbc775f850edebd99c4f6e7917f1832ace43c52c5e4d4b15bf10bf8f455889d4628");
        boolean boolean8 = colognePhonetic0.isEncodeEqual("c6699c7aa4c4899a7838b6472b6ae7719eda306fc3de2abefd814d5909c178da", "10101000111111110100010000111000000101000010010100111111011010001010100100100111001010010011101000010111011100000111001111101101010101011101000001101100000110100001010101000110001000101110010100100110101110111101101110100110111101111000011011100010001101011000111101100100000000000010010101011111010101110100101010100100101111101110010101100100101101011111011000011110100011110010110111100010110011110100010000111001100101010000001110001001111010010011011101101110011000110000111100110100011000101010100110111101");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms9 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.lang.String str10 = hmacAlgorithms9.getName();
        java.lang.String str11 = hmacAlgorithms9.toString();
        org.apache.commons.codec.digest.HmacUtils hmacUtils13 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms9, "c82c8ab22f3a62af4973396a2ad745b3");
        java.lang.String str14 = hmacAlgorithms9.getName();
        boolean boolean15 = org.apache.commons.codec.digest.HmacUtils.isAvailable(hmacAlgorithms9);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj16 = colognePhonetic0.encode((java.lang.Object) boolean15);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: This method's parameter was expected to be of the type java.lang.String. But actually it was of the type java.lang.Boolean.");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "" + "'", str2, "");
        org.junit.Assert.assertTrue("'" + boolean5 + "' != '" + false + "'", boolean5 == false);
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
        org.junit.Assert.assertTrue("'" + hmacAlgorithms9 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms9.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "HmacSHA224" + "'", str10, "HmacSHA224");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "HmacSHA224" + "'", str11, "HmacSHA224");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "HmacSHA224" + "'", str14, "HmacSHA224");
        org.junit.Assert.assertTrue("'" + boolean15 + "' != '" + true + "'", boolean15 == true);
    }

    @Test
    public void test2071() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2071");
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils3 = new org.apache.commons.codec.digest.DigestUtils(messageDigest2);
        byte[] byteArray9 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray9);
        java.lang.String str12 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray9, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str13 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray9);
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray9);
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray9);
        byte[] byteArray17 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray18 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray17);
        java.io.InputStream inputStream19 = java.io.InputStream.nullInputStream();
        java.lang.String str20 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray18, inputStream19);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream21 = new org.apache.commons.codec.binary.Base64InputStream(inputStream19);
        int int22 = base64InputStream21.available();
        byte[] byteArray23 = org.apache.commons.codec.digest.HmacUtils.hmacSha1(byteArray9, (java.io.InputStream) base64InputStream21);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream26 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base64InputStream21, false, true);
        java.security.MessageDigest messageDigest27 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest2, (java.io.InputStream) base64InputStream21);
        java.security.MessageDigest messageDigest28 = org.apache.commons.codec.digest.DigestUtils.getDigest("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1", messageDigest27);
        java.security.MessageDigest messageDigest29 = org.apache.commons.codec.digest.DigestUtils.getDigest("FPFFTPTK11", messageDigest28);
        java.io.RandomAccessFile randomAccessFile30 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray31 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest28, randomAccessFile30);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str10, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str12, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "AAAAAAA" + "'", str13, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str14, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str15, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream19);
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str20, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertTrue("'" + int22 + "' != '" + 1 + "'", int22 == 1);
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[-5, -37, 29, 27, 24, -86, 108, 8, 50, 75, 125, 100, -73, 31, -73, 99, 112, 105, 14, 29]");
        org.junit.Assert.assertNotNull(messageDigest27);
        org.junit.Assert.assertEquals(messageDigest27.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest28);
        org.junit.Assert.assertEquals(messageDigest28.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest29);
        org.junit.Assert.assertEquals(messageDigest29.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test2072() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2072");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha1("54d7107aa24bc36b8e80134b8e4ea34c0185bf226a305b9511a3711173b8f450e7494952770ec663d90fe5f906df8f27", "$1$cbK8kxeu$ELaOPtZMpKwQDVx7z0OMC.");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[2, 75, -108, 67, -99, -88, 54, -53, 94, -78, -49, 105, -105, -75, -68, 0, 110, -37, -19, 96]");
    }

    @Test
    public void test2073() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2073");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        java.nio.charset.Charset charset4 = qCodec3.getCharset();
        java.nio.charset.Charset charset5 = qCodec3.getCharset();
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec7 = new org.apache.commons.codec.net.QuotedPrintableCodec(charset5, true);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec8 = new org.apache.commons.codec.net.QuotedPrintableCodec(charset5);
        java.lang.String str10 = quotedPrintableCodec8.encode("8350e5a3e24c153df2275c9f80692773");
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator11 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) quotedPrintableCodec8);
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset4);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str10, "8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    public void test2074() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2074");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic0 = new org.apache.commons.codec.language.ColognePhonetic();
        java.lang.String str2 = colognePhonetic0.colognePhonetic("079564");
        java.lang.String str4 = colognePhonetic0.colognePhonetic("=E4=8B=B9=E0=A2=92=E9=94=AA=EB=9E=AE=EA=98=B3=E8=B9=A1=EF=86=8C=ED=81=AD=E8=\r\n=AF=97=CC=B6=D9=8F=E3=9B=8D=E2=8B=88=E5=AC=BC");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "" + "'", str2, "");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "01111382238123121818" + "'", str4, "01111382238123121818");
    }

    @Test
    public void test2075() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2075");
        org.apache.commons.codec.language.MatchRatingApproachEncoder matchRatingApproachEncoder0 = new org.apache.commons.codec.language.MatchRatingApproachEncoder();
        java.lang.String str2 = matchRatingApproachEncoder0.encode("bd0be5cc3381016e156ac44b77f4eb8f9fa98304fb499a95659142fe479acd17");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "BD0D17" + "'", str2, "BD0D17");
    }

    @Test
    public void test2076() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2076");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator3 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) soundex2);
        org.apache.commons.codec.language.bm.NameType nameType5 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType6 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet7 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap8 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType5, ruleType6, languageSet7);
        int int9 = stringEncoderComparator3.compare((java.lang.Object) "0Acd8L3u4hVxI", (java.lang.Object) ruleType6);
        java.lang.Object obj10 = null;
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.sha384("$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30");
        int int13 = stringEncoderComparator3.compare(obj10, (java.lang.Object) byteArray12);
        byte[] byteArray15 = org.apache.commons.codec.digest.DigestUtils.sha384("SHA-1");
        java.security.MessageDigest messageDigest18 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream19 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest20 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest18, inputStream19);
        java.security.MessageDigest messageDigest21 = org.apache.commons.codec.digest.DigestUtils.getDigest("$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1", messageDigest20);
        java.security.MessageDigest messageDigest22 = org.apache.commons.codec.digest.DigestUtils.getDigest("$apr1$A6$LH9Qf.ffx.HqGhcB8ODsl0", messageDigest20);
        int int23 = stringEncoderComparator3.compare((java.lang.Object) byteArray15, (java.lang.Object) messageDigest20);
        org.junit.Assert.assertTrue("'" + nameType5 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType5.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType6 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType6.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet7);
        org.junit.Assert.assertNotNull(strMap8);
        org.junit.Assert.assertTrue("'" + int9 + "' != '" + 0 + "'", int9 == 0);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[-52, 110, 77, -11, 61, -50, -33, 45, 79, 25, 89, -18, 82, 46, -127, -81, 25, -118, -11, 81, -37, 127, -92, 107, 17, -71, -36, 112, -109, -117, 62, 15, 89, -23, 70, -74, 70, -18, -99, 6, 108, 32, 10, -123, -125, -32, 14, -82]");
        org.junit.Assert.assertTrue("'" + int13 + "' != '" + 0 + "'", int13 == 0);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[94, -81, -34, -93, 111, 85, 21, -122, -91, 51, 5, 19, 65, 65, 60, -6, 74, 11, -111, -21, -81, -40, -24, -107, -32, 12, -76, -30, -114, -80, -20, 35, -13, 110, 45, -117, -35, 61, 121, 100, 114, -112, -92, 83, 8, 101, -14, 11]");
        org.junit.Assert.assertNotNull(messageDigest18);
        org.junit.Assert.assertEquals(messageDigest18.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream19);
        org.junit.Assert.assertNotNull(messageDigest20);
        org.junit.Assert.assertEquals(messageDigest20.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest21);
        org.junit.Assert.assertEquals(messageDigest21.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest22);
        org.junit.Assert.assertEquals(messageDigest22.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + int23 + "' != '" + 0 + "'", int23 == 0);
    }

    @Test
    public void test2077() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2077");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray4);
        pureJavaCrc32C0.update(byteArray4, (-690116322), (-1612190696));
        byte[] byteArray11 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray12 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray11);
        pureJavaCrc32C0.update(byteArray11);
        byte[] byteArray19 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray19);
        java.lang.String str22 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray19, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str23 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray19);
        byte[] byteArray24 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray11, byteArray19);
        byte[] byteArray26 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray27 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray26);
        java.io.InputStream inputStream28 = java.io.InputStream.nullInputStream();
        java.lang.String str29 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray27, inputStream28);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream30 = new org.apache.commons.codec.binary.Base64InputStream(inputStream28);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream31 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base64InputStream30);
        java.lang.String str32 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray11, (java.io.InputStream) base16InputStream31);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str20, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str22, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "AAAAAAA" + "'", str23, "AAAAAAA");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[44, 25, 81, 48, 24, -86, -111, -40, 44, -103, -115, 18, -39, 13, 31, -4, 55, -9, 40, 4, 100, -72, 12, -2, -68, 111, -122, -91, 123, -78, -42, 39, -106, -105, 87, -15, -32, 60, 52, -87, 78, 32, 122, 96, 104, 91, 55, -81]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream28);
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str29, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "c02f22f6013d1216269fc98d3db53a8b8083006a4f357b1ddf8ffd0b4ddd52f15e1ec73846cde22d19584aa4e0b46dcfb7b647a9bf6e4eb5c8a70e33eae241b2" + "'", str32, "c02f22f6013d1216269fc98d3db53a8b8083006a4f357b1ddf8ffd0b4ddd52f15e1ec73846cde22d19584aa4e0b46dcfb7b647a9bf6e4eb5c8a70e33eae241b2");
    }

    @Test
    public void test2078() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2078");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        boolean boolean3 = doubleMetaphone0.isDoubleMetaphoneEqual("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "7664fbe062101db016383ccc7d71037a073342cb0a161828f86315b6b9b06ed4053486c8d4f60dd3eb5eefa806facff24d12a98529fe15a02e986cca332ce518");
        java.lang.String str5 = doubleMetaphone0.doubleMetaphone("ash");
        org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult7 = doubleMetaphone0.new DoubleMetaphoneResult((int) (short) 100);
        java.lang.String str8 = doubleMetaphoneResult7.getPrimary();
        doubleMetaphoneResult7.append("$6$aXMHILof$fPCmrwTDKP8tgRiPtqfSVmcQzOW1qIhrD.i6V2/8GwacU7XIg3Ddqv8lo6b6knjXoaS0GEuA3UvBQb/Av1NXt.");
        doubleMetaphoneResult7.appendPrimary("\u1d74\u5560\u9deb\u2399\ue3a9\ue89d\uf686\uef20\u8b69\u2d45\ube17\ud2e2\u8c21\ufffd\u8d2e");
        doubleMetaphoneResult7.append('a', '4');
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "AX" + "'", str5, "AX");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "" + "'", str8, "");
    }

    @Test
    public void test2079() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2079");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        boolean boolean3 = doubleMetaphone0.isDoubleMetaphoneEqual("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "7664fbe062101db016383ccc7d71037a073342cb0a161828f86315b6b9b06ed4053486c8d4f60dd3eb5eefa806facff24d12a98529fe15a02e986cca332ce518");
        java.lang.String str5 = doubleMetaphone0.doubleMetaphone("ash");
        org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult7 = doubleMetaphone0.new DoubleMetaphoneResult((-1642666625));
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "AX" + "'", str5, "AX");
    }

    @Test
    public void test2080() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2080");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.lang.String str15 = quotedPrintableCodec1.getDefaultCharset();
        java.lang.String str17 = quotedPrintableCodec1.encode("2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str8, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str10, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "AAAAAAA" + "'", str11, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str12, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str13, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "UTF-8" + "'", str15, "UTF-8");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91" + "'", str17, "2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91");
    }

    @Test
    public void test2081() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2081");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("bd0be5cc3381016e156ac44b77f4eb8f9fa98304fb499a95659142fe479acd17", true);
    }

    @Test
    public void test2082() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2082");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms3 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        javax.crypto.Mac mac9 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms3, byteArray8);
        org.apache.commons.codec.digest.HmacUtils hmacUtils11 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms3, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream12 = null;
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy17 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream18 = new org.apache.commons.codec.binary.Base32InputStream(inputStream12, true, (int) (byte) 0, byteArray16, codecPolicy17);
        char[] charArray19 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray16);
        java.lang.String str20 = hmacUtils11.hmacHex(byteArray16);
        java.security.MessageDigest messageDigest21 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream22 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest23 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest21, inputStream22);
        java.lang.String str24 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream22);
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream22);
        java.lang.String str26 = hmacUtils11.hmacHex(inputStream22);
        org.apache.commons.codec.digest.XXHash32 xXHash32_28 = new org.apache.commons.codec.digest.XXHash32(0);
        xXHash32_28.reset();
        org.apache.commons.codec.binary.Hex hex30 = new org.apache.commons.codec.binary.Hex();
        java.security.MessageDigest messageDigest31 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer33 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest34 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest31, byteBuffer33);
        char[] charArray36 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer33, true);
        byte[] byteArray37 = hex30.decode(byteBuffer33);
        xXHash32_28.update(byteBuffer33);
        byte[] byteArray39 = hmacUtils11.hmac(byteBuffer33);
        java.lang.String str40 = org.apache.commons.codec.binary.Hex.encodeHexString(byteBuffer33);
        java.security.MessageDigest messageDigest41 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteBuffer33);
        java.io.RandomAccessFile randomAccessFile42 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray43 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, randomAccessFile42);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms3 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms3.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac9);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy17 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy17.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray19);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray19), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray19), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray19), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str20, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertNotNull(messageDigest21);
        org.junit.Assert.assertEquals(messageDigest21.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream22);
        org.junit.Assert.assertNotNull(messageDigest23);
        org.junit.Assert.assertEquals(messageDigest23.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str24, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9" + "'", str26, "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9");
        org.junit.Assert.assertNotNull(messageDigest31);
        org.junit.Assert.assertEquals(messageDigest31.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer33);
        org.junit.Assert.assertNotNull(messageDigest34);
        org.junit.Assert.assertEquals(messageDigest34.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray36);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray36), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray36), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray36), "[]");
        org.junit.Assert.assertNotNull(byteArray37);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray37), "[]");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[-101, -34, -57, -84, -23, -76, -37, -115, 67, 87, -100, -83, -67, 9, -22, 96, -118, 21, -19, 105, 126, -18, -106, 21, -117, 25, -52, -55]");
        org.junit.Assert.assertEquals("'" + str40 + "' != '" + "" + "'", str40, "");
        org.junit.Assert.assertNotNull(messageDigest41);
        org.junit.Assert.assertEquals(messageDigest41.toString(), "SHA-512 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test2083() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2083");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        long long9 = base64InputStream5.skip((long) ' ');
        base64InputStream5.mark((int) (short) 10);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.md5Hex((java.io.InputStream) base64InputStream5);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha256((java.io.InputStream) base64InputStream5);
        int int14 = base64InputStream5.read();
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertTrue("'" + long9 + "' != '" + 0L + "'", long9 == 0L);
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "d41d8cd98f00b204e9800998ecf8427e" + "'", str12, "d41d8cd98f00b204e9800998ecf8427e");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-29, -80, -60, 66, -104, -4, 28, 20, -102, -5, -12, -56, -103, 111, -71, 36, 39, -82, 65, -28, 100, -101, -109, 76, -92, -107, -103, 27, 120, 82, -72, 85]");
        org.junit.Assert.assertTrue("'" + int14 + "' != '" + (-1) + "'", int14 == (-1));
    }

    @Test
    public void test2084() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2084");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384("84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        byte[] byteArray3 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray4 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray3);
        java.io.InputStream inputStream5 = java.io.InputStream.nullInputStream();
        java.lang.String str6 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray4, inputStream5);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream7 = new org.apache.commons.codec.binary.Base64InputStream(inputStream5);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.md2Hex(inputStream5);
        java.lang.String str9 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex(byteArray1, inputStream5);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-47, -33, -30, -56, 56, -119, -99, -39, 27, 41, 78, 82, -41, -121, 37, 0, -44, 16, 125, -51, -104, 41, 96, 35, 33, 106, -114, -58, -40, 76, -107, 23, -45, 107, 49, -81, 86, -109, -70, -50, 106, -125, -115, 66, 60, -35, 74, 0]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str6, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str8, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "ed00bb29a590c0c5954608e3f9a6c00456b620eb3dbac3a69551440edad0cf3f79d3f4b5cbad10cabded3fa679617dc2" + "'", str9, "ed00bb29a590c0c5954608e3f9a6c00456b620eb3dbac3a69551440edad0cf3f79d3f4b5cbad10cabded3fa679617dc2");
    }

    @Test
    public void test2085() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2085");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.NameType nameType2 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType3 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet4 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap5 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType2, ruleType3, languageSet4);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap7 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType3, languageSet6);
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder8 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        boolean boolean9 = beiderMorseEncoder8.isConcat();
        org.apache.commons.codec.language.bm.NameType nameType10 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang11 = org.apache.commons.codec.language.bm.Lang.instance(nameType10);
        org.apache.commons.codec.language.bm.NameType nameType12 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder13 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType14 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder13.setRuleType(ruleType14);
        org.apache.commons.codec.language.bm.NameType nameType16 = beiderMorseEncoder13.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType17 = beiderMorseEncoder13.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet18 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap19 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType12, ruleType17, languageSet18);
        org.apache.commons.codec.language.bm.NameType nameType20 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang21 = org.apache.commons.codec.language.bm.Lang.instance(nameType20);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet23 = lang21.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet25 = lang21.guessLanguages("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap26 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType10, ruleType17, languageSet25);
        org.apache.commons.codec.language.bm.RuleType ruleType27 = org.apache.commons.codec.language.bm.RuleType.APPROX;
        org.apache.commons.codec.language.bm.NameType nameType28 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang29 = org.apache.commons.codec.language.bm.Lang.instance(nameType28);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet31 = lang29.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet33 = lang29.guessLanguages("400000");
        java.lang.String str34 = languageSet33.getAny();
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap35 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType10, ruleType27, languageSet33);
        beiderMorseEncoder8.setRuleType(ruleType27);
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine38 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType27, true);
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertTrue("'" + nameType2 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType2.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet4);
        org.junit.Assert.assertNotNull(strMap5);
        org.junit.Assert.assertNotNull(languageSet6);
        org.junit.Assert.assertNotNull(strMap7);
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + true + "'", boolean9 == true);
        org.junit.Assert.assertTrue("'" + nameType10 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType10.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang11);
        org.junit.Assert.assertTrue("'" + nameType12 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType12.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType14 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType14.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType16 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType16.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType17 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType17.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet18);
        org.junit.Assert.assertNotNull(strMap19);
        org.junit.Assert.assertTrue("'" + nameType20 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType20.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang21);
        org.junit.Assert.assertNotNull(languageSet23);
        org.junit.Assert.assertNotNull(languageSet25);
        org.junit.Assert.assertNotNull(strMap26);
        org.junit.Assert.assertTrue("'" + ruleType27 + "' != '" + org.apache.commons.codec.language.bm.RuleType.APPROX + "'", ruleType27.equals(org.apache.commons.codec.language.bm.RuleType.APPROX));
        org.junit.Assert.assertTrue("'" + nameType28 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType28.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang29);
        org.junit.Assert.assertNotNull(languageSet31);
        org.junit.Assert.assertNotNull(languageSet33);
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "greek" + "'", str34, "greek");
        org.junit.Assert.assertNotNull(strMap35);
    }

    @Test
    public void test2086() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2086");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        doubleMetaphone0.setMaxCodeLen((int) (byte) 100);
        java.lang.String str4 = doubleMetaphone0.doubleMetaphone("I6ae");
        java.lang.String str7 = doubleMetaphone0.doubleMetaphone("Ae3f", false);
        java.lang.String str9 = doubleMetaphone0.doubleMetaphone("\ub7d6\u3e3d\u0ba4\uec30\ufffd\u0de8\u13cd\u11b6\u0c18\u9b67\ucb69\u4a58\u9d92");
        java.lang.String str11 = doubleMetaphone0.doubleMetaphone("QUdnQWFRQWg=");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "A" + "'", str4, "A");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "AF" + "'", str7, "AF");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "" + "'", str9, "");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "KTNKFRKK" + "'", str11, "KTNKFRKK");
    }

    @Test
    public void test2087() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2087");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream4 = new org.apache.commons.codec.binary.Base16InputStream(inputStream1, false);
        int int5 = base16InputStream4.available();
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex((java.io.InputStream) base16InputStream4);
        org.apache.commons.codec.binary.Base64 base64_9 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy10 = base64_9.getCodecPolicy();
        org.apache.commons.codec.binary.Base16 base16_11 = new org.apache.commons.codec.binary.Base16(false, codecPolicy10);
        byte[] byteArray17 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray17);
        java.lang.String str20 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray17, false);
        byte[] byteArray21 = org.apache.commons.codec.digest.Blake3.hash(byteArray17);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray17);
        long long23 = org.apache.commons.codec.digest.MurmurHash3.hash64(byteArray17);
        javax.crypto.Mac mac24 = org.apache.commons.codec.digest.HmacUtils.getHmacSha384(byteArray17);
        java.lang.String str25 = base16_11.encodeAsString(byteArray17);
        java.lang.String str26 = org.apache.commons.codec.binary.StringUtils.newStringIso8859_1(byteArray17);
        char[] charArray27 = org.apache.commons.codec.binary.Hex.encodeHex(byteArray17);
        // The following exception was thrown during execution in test generation
        try {
            int int30 = base16InputStream4.read(byteArray17, (-557514842), (-488200341));
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: null");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + int5 + "' != '" + 1 + "'", int5 == 1);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertTrue("'" + codecPolicy10 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy10.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str18, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "0A01640101" + "'", str20, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62" + "'", str22, "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
        org.junit.Assert.assertTrue("'" + long23 + "' != '" + (-7793026892456512543L) + "'", long23 == (-7793026892456512543L));
        org.junit.Assert.assertNotNull(mac24);
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "0A01640101" + "'", str25, "0A01640101");
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "\n\001d\001\001" + "'", str26, "\n\001d\001\001");
        org.junit.Assert.assertNotNull(charArray27);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray27), "0a01640101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray27), "0a01640101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray27), "[0, a, 0, 1, 6, 4, 0, 1, 0, 1]");
    }

    @Test
    public void test2088() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2088");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("7516c70c482edf6875ceeebcf2f59b6e1710acbc432fa2c0f4c9551661568709b30b8b3c4025be1396f0885b975b8beba34be8451a6f8adf33ed1480ebd15181", "P242");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm 7516c70c482edf6875ceeebcf2f59b6e1710acbc432fa2c0f4c9551661568709b30b8b3c4025be1396f0885b975b8beba34be8451a6f8adf33ed1480ebd15181 not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test2089() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2089");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUsAscii("$1$cbK8kxeu$ELaOPtZMpKwQDVx7z0OMC.");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[36, 49, 36, 99, 98, 75, 56, 107, 120, 101, 117, 36, 69, 76, 97, 79, 80, 116, 90, 77, 112, 75, 119, 81, 68, 86, 120, 55, 122, 48, 79, 77, 67, 46]");
    }

    @Test
    public void test2090() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2090");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec5 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray11 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray11);
        java.lang.String str14 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray11, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str15 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray11);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray11);
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray11);
        java.lang.Object obj18 = quotedPrintableCodec5.decode((java.lang.Object) byteArray11);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream19 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1, true, 1, byteArray11);
        byte[] byteArray24 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str25 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray24);
        java.lang.String str26 = org.apache.commons.codec.binary.StringUtils.newStringUtf16Be(byteArray24);
        java.nio.charset.Charset charset27 = org.apache.commons.codec.Charsets.UTF_16;
        org.apache.commons.codec.binary.Base64 base64_29 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy30 = base64_29.getCodecPolicy();
        org.apache.commons.codec.net.BCodec bCodec31 = new org.apache.commons.codec.net.BCodec(charset27, codecPolicy30);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream32 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1, true, (int) (short) 1, byteArray24, codecPolicy30);
        base64OutputStream32.write(0);
        base64OutputStream32.close();
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str12, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str14, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "AAAAAAA" + "'", str15, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str16, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str17, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj18);
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "\000\ufffd" + "'", str25, "\000\ufffd");
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "\377" + "'", str26, "\377");
        org.junit.Assert.assertNotNull(charset27);
        org.junit.Assert.assertTrue("'" + codecPolicy30 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy30.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test2091() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2091");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray5);
        java.lang.String str13 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str11, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "\000\000\000\000\000" + "'", str12, "\000\000\000\000\000");
// flaky:         org.junit.Assert.assertEquals("'" + str13 + "' != '" + "$6$bt0obfx4$9N/kQej7FHHzHPClsv9mWlX0Dek9n9x/tfllfYgLIw86TZbpvgH/TBLAZ0PQFXXuFeHZ/6skHpkos8rx7kXwc0" + "'", str13, "$6$bt0obfx4$9N/kQej7FHHzHPClsv9mWlX0Dek9n9x/tfllfYgLIw86TZbpvgH/TBLAZ0PQFXXuFeHZ/6skHpkos8rx7kXwc0");
    }

    @Test
    public void test2092() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2092");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md2("798543");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[64, 116, 86, 22, 6, -14, -32, 103, 92, 55, -100, 68, -33, -70, 3, -106]");
    }

    @Test
    public void test2093() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2093");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray8, false);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, byteArray8);
        org.apache.commons.codec.digest.Blake3 blake3_13 = org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction(byteArray2);
        byte[] byteArray14 = org.apache.commons.codec.binary.Base64.decodeBase64(byteArray2);
        java.security.MessageDigest messageDigest19 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest20 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest19);
        java.nio.ByteBuffer byteBuffer22 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        byte[] byteArray23 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest19, byteBuffer22);
        char[] charArray24 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray23);
        org.apache.commons.codec.binary.Hex.encodeHex(byteArray2, (int) (short) 1, (-1310417787), false, charArray24, 1708909655);
        boolean boolean27 = org.apache.commons.codec.binary.Base64.isBase64(byteArray2);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0A01640101" + "'", str11, "0A01640101");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str12, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertNotNull(blake3_13);
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[18, 85, 49, 84, 49, 62, 75, -31]");
        org.junit.Assert.assertNotNull(messageDigest19);
        org.junit.Assert.assertEquals(messageDigest19.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest20);
        org.junit.Assert.assertEquals(messageDigest20.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteBuffer22);
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[-99, -100, 49, -97, 2, -122, 80, -111, -15, 37, 12, 117, -65, 27, -89, 78, 99, -88, 116, -118, -52, 81, 70, 55, 112, -19, 51, -79, 52, -22, -103, -31, -100, -50, 83, 84, -24, -52, -24, -5, 46, -124, -89, 47, -93, 90, 18, 13]");
        org.junit.Assert.assertNotNull(charArray24);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray24), "000011010001001001011010101000110010111110100111100001000010111011111011111010001100110011101000010101000101001111001110100111001110000110011001111010100011010010110001001100111110110101110000001101110100011001010001110011001000101001110100101010000110001101001110101001110001101110111111011101010000110000100101111100011001000101010000100001100000001010011111001100011001110010011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray24), "000011010001001001011010101000110010111110100111100001000010111011111011111010001100110011101000010101000101001111001110100111001110000110011001111010100011010010110001001100111110110101110000001101110100011001010001110011001000101001110100101010000110001101001110101001110001101110111111011101010000110000100101111100011001000101010000100001100000001010011111001100011001110010011101");
        org.junit.Assert.assertTrue("'" + boolean27 + "' != '" + false + "'", boolean27 == false);
    }

    @Test
    public void test2094() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2094");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        java.lang.String str4 = soundex2.soundex("MPMF");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "Mb13" + "'", str4, "Mb13");
    }

    @Test
    public void test2095() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2095");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms3 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        javax.crypto.Mac mac9 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms3, byteArray8);
        byte[] byteArray15 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray15);
        java.lang.String str18 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray15, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str19 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray15);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray15);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray15);
        javax.crypto.Mac mac22 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms3, byteArray15);
        org.apache.commons.codec.binary.Base32 base32_24 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet25 = null;
        byte[] byteArray27 = new byte[] { (byte) 100 };
        byte[] byteArray28 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet25, byteArray27);
        byte[] byteArray29 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray28);
        boolean boolean31 = base32_24.isInAlphabet(byteArray29, false);
        byte[] byteArray33 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str34 = base32_24.encodeAsString(byteArray33);
        org.apache.commons.codec.digest.HmacUtils hmacUtils35 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms3, byteArray33);
        java.security.MessageDigest messageDigest36 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest2, byteArray33);
        org.apache.commons.codec.digest.DigestUtils digestUtils37 = new org.apache.commons.codec.digest.DigestUtils(messageDigest36);
        java.security.MessageDigest messageDigest39 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest40 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest39);
        java.nio.ByteBuffer byteBuffer42 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        byte[] byteArray43 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest39, byteBuffer42);
        java.lang.String str44 = org.apache.commons.codec.binary.Hex.encodeHexString(byteBuffer42);
        java.lang.String str45 = digestUtils37.digestAsHex(byteBuffer42);
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms3 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms3.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac9);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str16, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str18, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "AAAAAAA" + "'", str19, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str20, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str21, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac22);
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[100]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[100]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean31 + "' != '" + false + "'", boolean31 == false);
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "ABUAA2IAEE======" + "'", str34, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(messageDigest36);
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest39);
        org.junit.Assert.assertEquals(messageDigest39.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest40);
        org.junit.Assert.assertEquals(messageDigest40.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteBuffer42);
        org.junit.Assert.assertNotNull(byteArray43);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray43), "[-99, -100, 49, -97, 2, -122, 80, -111, -15, 37, 12, 117, -65, 27, -89, 78, 99, -88, 116, -118, -52, 81, 70, 55, 112, -19, 51, -79, 52, -22, -103, -31, -100, -50, 83, 84, -24, -52, -24, -5, 46, -124, -89, 47, -93, 90, 18, 13]");
        org.junit.Assert.assertEquals("'" + str44 + "' != '" + "" + "'", str44, "");
        org.junit.Assert.assertEquals("'" + str45 + "' != '" + "01118df906a97646cfc8587e18c99189855dea2d3a76ecfbf9b9716d6bff07952c55e6320079cc7b6e353b0718c3effe" + "'", str45, "01118df906a97646cfc8587e18c99189855dea2d3a76ecfbf9b9716d6bff07952c55e6320079cc7b6e353b0718c3effe");
    }

    @Test
    public void test2096() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2096");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        boolean boolean3 = doubleMetaphone0.isDoubleMetaphoneEqual("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "7664fbe062101db016383ccc7d71037a073342cb0a161828f86315b6b9b06ed4053486c8d4f60dd3eb5eefa806facff24d12a98529fe15a02e986cca332ce518");
        java.lang.String str5 = doubleMetaphone0.doubleMetaphone("ash");
        doubleMetaphone0.setMaxCodeLen((int) (byte) 10);
        boolean boolean11 = doubleMetaphone0.isDoubleMetaphoneEqual("kabevdegdZafkebbeadZadpfbbdetf|kabevdegdZafkebbeakadpfbbdetf|kabevdegdZavdZebbeadZadpfbbdetf|kabevdegdZavdZebbeakadpfbbdetf|kabevdekafkebbajakadpfbbdetf|kabevdekafkebbeadZadpfbbdetf|kabevdekafkebbeakadpfbbdetf|kabevdekafkebbeatsadpfbbdetf|kabevdekafkebbiakadpfbbdetf|kabevdekaftsebbeakadpfbbdetf|kabevdekaftsebbeatsadpfbbdetf|kabevdekavdZebbeadZadpfbbdetf|kabevdekavdZebbeakadpfbbdetf|kabevdektsafkebbeakadpfbbdetf|kabevdektsafkebbeatsadpfbbdetf|kabevdektsaftsebbeakadpfbbdetf|kabevdektsaftsebbeatsadpfbbdetf|kabevdetskafkebbeakadpfbbdetf|kabevdetskafkebbeatsadpfbbdetf|kabevdetskaftsebbeakadpfbbdetf", "vdefadpkfbatvdaeaebbgdptkfbbp|vdefadpkfbatvdajaebbgdptkfbbp", true);
        java.lang.Object obj13 = doubleMetaphone0.encode((java.lang.Object) "11d28c31c65926cb6fe98aa02cdcddc71bf3d9e28f39a780ef64083332aa535851d5df9fbcf61fee0d8d909aa1b46a9a");
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "AX" + "'", str5, "AX");
        org.junit.Assert.assertTrue("'" + boolean11 + "' != '" + false + "'", boolean11 == false);
        org.junit.Assert.assertEquals("'" + obj13 + "' != '" + "TKKKPFKTKT" + "'", obj13, "TKKKPFKTKT");
    }

    @Test
    public void test2097() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2097");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream6 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3, true);
        org.apache.commons.codec.binary.Base32InputStream base32InputStream7 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base64InputStream6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.md5Hex((java.io.InputStream) base64InputStream6);
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.sha1("6brp3ObrccRZI");
        org.apache.commons.codec.binary.Base32InputStream base32InputStream13 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base64InputStream6, false, (int) (short) -1, byteArray12);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "d41d8cd98f00b204e9800998ecf8427e" + "'", str8, "d41d8cd98f00b204e9800998ecf8427e");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[-9, 84, 34, 7, 122, 34, 10, -86, -42, 81, -86, 18, -122, 11, -20, 15, -85, 77, -48, -13]");
    }

    @Test
    public void test2098() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2098");
        java.io.InputStream inputStream0 = java.io.InputStream.nullInputStream();
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream0);
        org.apache.commons.codec.binary.Base32InputStream base32InputStream2 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0);
        int int3 = base32InputStream2.read();
        int int4 = base32InputStream2.available();
        org.junit.Assert.assertNotNull(inputStream0);
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str1, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + (-1) + "'", int3 == (-1));
        org.junit.Assert.assertTrue("'" + int4 + "' != '" + 0 + "'", int4 == 0);
    }

    @Test
    public void test2099() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2099");
        org.apache.commons.codec.language.Soundex soundex0 = org.apache.commons.codec.language.Soundex.US_ENGLISH;
        soundex0.setMaxLength((-1612190696));
        java.lang.String str4 = soundex0.encode("dba775cd82010b877fd28af00fbcb6db02bfa1f71407c48744737ad5dd19b6f1");
        java.lang.String str6 = soundex0.encode("719bf945849ee63ffc9d5309e5b1e33132b379d99fcc6e853ec673a5e826801a");
        org.junit.Assert.assertNotNull(soundex0);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "D123" + "'", str4, "D123");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "B123" + "'", str6, "B123");
    }

    @Test
    public void test2100() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2100");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        long long1 = xXHash32_0.getValue();
        xXHash32_0.reset();
        xXHash32_0.update((int) (byte) 100);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_224("SHA3-256");
        byte[] byteArray7 = org.apache.commons.codec.net.URLCodec.decodeUrl(byteArray6);
        java.lang.String str8 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray6);
        xXHash32_0.update(byteArray6);
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.md2(byteArray6);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + 46947589L + "'", long1 == 46947589L);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "t9Y+PQuk7DDZsoNwDegTzRG2DBibZ8tpSlidkg==" + "'", str8, "t9Y+PQuk7DDZsoNwDegTzRG2DBibZ8tpSlidkg==");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[-87, -60, 18, -68, 71, -27, 69, 16, -98, 99, -37, 9, 27, 110, -28, -77]");
    }

    @Test
    public void test2101() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2101");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224("1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2, true);
        byte[] byteArray10 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray10);
        java.lang.String str13 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray10, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str14 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray10);
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray10);
        java.lang.String str17 = org.apache.commons.codec.digest.Crypt.crypt(byteArray10, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec19 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet20 = null;
        byte[] byteArray22 = new byte[] { (byte) 100 };
        byte[] byteArray23 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet20, byteArray22);
        byte[] byteArray24 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray23);
        byte[] byteArray25 = uRLCodec19.encode(byteArray24);
        java.lang.String str26 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray10, byteArray24);
        byte[] byteArray27 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray10);
        java.io.InputStream inputStream28 = java.io.InputStream.nullInputStream();
        java.lang.String str29 = org.apache.commons.codec.digest.DigestUtils.md5Hex(inputStream28);
        byte[] byteArray30 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray10, inputStream28);
        byte[] byteArray31 = org.apache.commons.codec.digest.DigestUtils.sha3_224(inputStream28);
        java.lang.String str32 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex(byteArray4, inputStream28);
        org.apache.commons.codec.digest.Blake3 blake3_33 = org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction(byteArray4);
        char[] charArray34 = org.apache.commons.codec.binary.Hex.encodeHex(byteArray4);
        java.lang.String str36 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray4, "KTNKFRKK");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-126, 10, -21, -56, -47, -28, 44, -55, 21, -15, 0, 121, -124, -31, -41, -30, 23, 37, 17, 42, 61, -45, 71, 4, -44, -99, -55, -72]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str11, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str13, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "AAAAAAA" + "'", str14, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str15, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "0Acd8L3u4hVxI" + "'", str17, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[100]");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[100]");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str26, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(inputStream28);
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "d41d8cd98f00b204e9800998ecf8427e" + "'", str29, "d41d8cd98f00b204e9800998ecf8427e");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[-74, 19, 103, -102, 8, 20, -39, -20, 119, 47, -107, -41, 120, -61, 95, -59, -1, 22, -105, -60, -109, 113, 86, 83, -58, -57, 18, 20, 66, -110, -59, -83]");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[107, 78, 3, 66, 54, 103, -37, -73, 59, 110, 21, 69, 79, 14, -79, -85, -44, 89, 127, -102, 27, 7, -114, 63, 91, 90, 107, -57]");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "57f33d9ef78f27a3d8b3c4f7391b148a6037aa0dfdae6a7eb1bcdd008039bd18d360c50131fb81238b530791614369b5" + "'", str32, "57f33d9ef78f27a3d8b3c4f7391b148a6037aa0dfdae6a7eb1bcdd008039bd18d360c50131fb81238b530791614369b5");
        org.junit.Assert.assertNotNull(blake3_33);
        org.junit.Assert.assertNotNull(charArray34);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray34), "3d38323d30413d45423d43383d44313d45342c3d43393d31353d46313d3030793d38343d45313d44373d45323d3137253d31312a3d33443d4433473d30343d44343d39443d43393d4238");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray34), "3d38323d30413d45423d43383d44313d45342c3d43393d31353d46313d3030793d38343d45313d44373d45323d3137253d31312a3d33443d4433473d30343d44343d39443d43393d4238");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray34), "[3, d, 3, 8, 3, 2, 3, d, 3, 0, 4, 1, 3, d, 4, 5, 4, 2, 3, d, 4, 3, 3, 8, 3, d, 4, 4, 3, 1, 3, d, 4, 5, 3, 4, 2, c, 3, d, 4, 3, 3, 9, 3, d, 3, 1, 3, 5, 3, d, 4, 6, 3, 1, 3, d, 3, 0, 3, 0, 7, 9, 3, d, 3, 8, 3, 4, 3, d, 4, 5, 3, 1, 3, d, 4, 4, 3, 7, 3, d, 4, 5, 3, 2, 3, d, 3, 1, 3, 7, 2, 5, 3, d, 3, 1, 3, 1, 2, a, 3, d, 3, 3, 4, 4, 3, d, 4, 4, 3, 3, 4, 7, 3, d, 3, 0, 3, 4, 3, d, 4, 4, 3, 4, 3, d, 3, 9, 4, 4, 3, d, 4, 3, 3, 9, 3, d, 4, 2, 3, 8]");
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "$apr1$KTNKFRKK$NCo9GWSOS8Cqyvcynkrhb." + "'", str36, "$apr1$KTNKFRKK$NCo9GWSOS8Cqyvcynkrhb.");
    }

    @Test
    public void test2102() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2102");
        org.apache.commons.codec.language.bm.Rule.PhonemeExpr phonemeExpr3 = null;
        org.apache.commons.codec.language.bm.Rule rule4 = new org.apache.commons.codec.language.bm.Rule("d7bXONth0AIyo", "ABUAA2IAEE======", "org.apache.commons.codec.DecoderException: org.apache.commons.codec.EncoderException", phonemeExpr3);
        org.apache.commons.codec.language.bm.Rule.RPattern rPattern5 = rule4.getRContext();
        org.apache.commons.codec.language.bm.Rule.RPattern rPattern6 = rule4.getRContext();
        org.apache.commons.codec.language.bm.Rule.PhonemeExpr phonemeExpr7 = rule4.getPhoneme();
        org.apache.commons.codec.language.bm.Rule.RPattern rPattern8 = rule4.getRContext();
        org.junit.Assert.assertNotNull(rPattern5);
        org.junit.Assert.assertNotNull(rPattern6);
        org.junit.Assert.assertNull(phonemeExpr7);
        org.junit.Assert.assertNotNull(rPattern8);
    }

    @Test
    public void test2103() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2103");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        org.apache.commons.codec.binary.Base16InputStream base16InputStream4 = new org.apache.commons.codec.binary.Base16InputStream(inputStream1, false);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream1);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex((java.io.InputStream) base64InputStream5);
        int int7 = base64InputStream5.read();
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.md2((java.io.InputStream) base64InputStream5);
        // The following exception was thrown during execution in test generation
        try {
            base64InputStream5.reset();
            org.junit.Assert.fail("Expected exception of type java.io.IOException; message: mark/reset not supported");
        } catch (java.io.IOException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str6, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        org.junit.Assert.assertTrue("'" + int7 + "' != '" + (-1) + "'", int7 == (-1));
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[-125, 80, -27, -93, -30, 76, 21, 61, -14, 39, 92, -97, -128, 105, 39, 115]");
    }

    @Test
    public void test2104() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2104");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        int int6 = base64InputStream5.available();
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_224((java.io.InputStream) base64InputStream5);
        boolean boolean8 = org.apache.commons.codec.binary.Base64.isBase64(byteArray7);
        byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.md2(byteArray7);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertTrue("'" + int6 + "' != '" + 1 + "'", int6 == 1);
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[107, 78, 3, 66, 54, 103, -37, -73, 59, 110, 21, 69, 79, 14, -79, -85, -44, 89, 127, -102, 27, 7, -114, 63, 91, 90, 107, -57]");
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[-54, 54, -69, -22, -46, -29, -113, 100, -9, 33, 66, -68, 127, 14, 58, -56]");
    }

    @Test
    public void test2105() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2105");
        java.io.InputStream inputStream0 = java.io.InputStream.nullInputStream();
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream0);
        org.apache.commons.codec.binary.Hex hex4 = new org.apache.commons.codec.binary.Hex();
        java.security.MessageDigest messageDigest5 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer7 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest5, byteBuffer7);
        char[] charArray10 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer7, true);
        byte[] byteArray11 = hex4.decode(byteBuffer7);
        byte[] byteArray14 = org.apache.commons.codec.digest.HmacUtils.hmacMd5("org.apache.commons.codec.EncoderException", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        boolean boolean15 = org.apache.commons.codec.binary.Base64.isArrayByteBase64(byteArray14);
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha384(byteArray14);
        byte[] byteArray17 = hex4.encode(byteArray14);
        byte[] byteArray19 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray20 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray19);
        java.io.InputStream inputStream21 = java.io.InputStream.nullInputStream();
        java.lang.String str22 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray20, inputStream21);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream23 = new org.apache.commons.codec.binary.Base64InputStream(inputStream21);
        byte[] byteArray24 = org.apache.commons.codec.digest.DigestUtils.sha512(inputStream21);
        byte[] byteArray25 = hex4.encode(byteArray24);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32InputStream base32InputStream26 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, false, 1254840318, byteArray24);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain Base32 characters: [??5~??T(P?m??? ???W????!?l??G??<]??????~?/c?1?GAz??82z?'?>]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(inputStream0);
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str1, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertNotNull(messageDigest5);
        org.junit.Assert.assertEquals(messageDigest5.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer7);
        org.junit.Assert.assertNotNull(messageDigest8);
        org.junit.Assert.assertEquals(messageDigest8.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray10);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray10), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray10), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray10), "[]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[-52, -57, 74, -6, 47, 76, -27, -67, -45, 6, -86, 70, -26, -31, -14, -84]");
        org.junit.Assert.assertTrue("'" + boolean15 + "' != '" + false + "'", boolean15 == false);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[123, -52, -70, 4, 44, 20, -30, 19, -98, -42, -48, -37, 77, -68, 121, -20, -49, 120, 18, 38, -52, -102, -127, -67, 33, -121, -42, -83, 103, -35, 39, 28, -18, -18, 120, 25, -67, 95, -87, -2, -79, -14, -112, -12, 40, -32, -21, 124]");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[99, 99, 99, 55, 52, 97, 102, 97, 50, 102, 52, 99, 101, 53, 98, 100, 100, 51, 48, 54, 97, 97, 52, 54, 101, 54, 101, 49, 102, 50, 97, 99]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream21);
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str22, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[-49, -125, -31, 53, 126, -17, -72, -67, -15, 84, 40, 80, -42, 109, -128, 7, -42, 32, -28, 5, 11, 87, 21, -36, -125, -12, -87, 33, -45, 108, -23, -50, 71, -48, -47, 60, 93, -123, -14, -80, -1, -125, 24, -46, -121, 126, -20, 47, 99, -71, 49, -67, 71, 65, 122, -127, -91, 56, 50, 122, -7, 39, -38, 62]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[99, 102, 56, 51, 101, 49, 51, 53, 55, 101, 101, 102, 98, 56, 98, 100, 102, 49, 53, 52, 50, 56, 53, 48, 100, 54, 54, 100, 56, 48, 48, 55, 100, 54, 50, 48, 101, 52, 48, 53, 48, 98, 53, 55, 49, 53, 100, 99, 56, 51, 102, 52, 97, 57, 50, 49, 100, 51, 54, 99, 101, 57, 99, 101, 52, 55, 100, 48, 100, 49, 51, 99, 53, 100, 56, 53, 102, 50, 98, 48, 102, 102, 56, 51, 49, 56, 100, 50, 56, 55, 55, 101, 101, 99, 50, 102, 54, 51, 98, 57, 51, 49, 98, 100, 52, 55, 52, 49, 55, 97, 56, 49, 97, 53, 51, 56, 51, 50, 55, 97, 102, 57, 50, 55, 100, 97, 51, 101]");
    }

    @Test
    public void test2106() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2106");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.md5(inputStream3);
        java.security.MessageDigest messageDigest9 = org.apache.commons.codec.digest.DigestUtils.getSha512_224Digest();
        byte[] byteArray11 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray12 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray11);
        java.io.InputStream inputStream13 = java.io.InputStream.nullInputStream();
        java.lang.String str14 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray12, inputStream13);
        byte[] byteArray15 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest9, byteArray12);
        org.apache.commons.codec.binary.Base32 base32_17 = new org.apache.commons.codec.binary.Base32((int) (short) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy18 = base32_17.getCodecPolicy();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream19 = new org.apache.commons.codec.binary.Base32InputStream(inputStream3, true, (int) (byte) 0, byteArray15, codecPolicy18);
        boolean boolean20 = base32InputStream19.isStrictDecoding();
        byte[] byteArray24 = org.apache.commons.codec.digest.DigestUtils.sha3_512("");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64InputStream base64InputStream25 = new org.apache.commons.codec.binary.Base64InputStream((java.io.InputStream) base32InputStream19, true, 275646681, byteArray24);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [??s?:???g??Zun???O?XY????G\\?????:???L???@,:?X?????????u??(??&]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126]");
        org.junit.Assert.assertNotNull(messageDigest9);
        org.junit.Assert.assertEquals(messageDigest9.toString(), "SHA-512/224 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream13);
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str14, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[-6, -46, 89, 81, 20, -27, -60, 90, -119, 111, 52, -127, -69, 99, -25, 9, 127, -97, 16, 111, -45, 89, 28, 30, 55, -61, 15, -18]");
        org.junit.Assert.assertTrue("'" + codecPolicy18 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy18.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertTrue("'" + boolean20 + "' != '" + false + "'", boolean20 == false);
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[-90, -97, 115, -52, -94, 58, -102, -59, -56, -75, 103, -36, 24, 90, 117, 110, -105, -55, -126, 22, 79, -30, 88, 89, -32, -47, -36, -63, 71, 92, -128, -90, 21, -78, 18, 58, -15, -11, -7, 76, 17, -29, -23, 64, 44, 58, -59, 88, -11, 0, 25, -99, -107, -74, -45, -29, 1, 117, -123, -122, 40, 29, -51, 38]");
    }

    @Test
    public void test2107() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2107");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32(1);
    }

    @Test
    public void test2108() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2108");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5;
        org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "UTF-8");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C3 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C3.reset();
        java.util.BitSet bitSet5 = null;
        byte[] byteArray7 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray8 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet5, byteArray7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray7);
        pureJavaCrc32C3.update(byteArray7, (-690116322), (-1612190696));
        byte[] byteArray14 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray15 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray14);
        pureJavaCrc32C3.update(byteArray14);
        org.apache.commons.codec.digest.HmacUtils hmacUtils17 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, byteArray14);
        boolean boolean18 = org.apache.commons.codec.digest.HmacUtils.isAvailable(hmacAlgorithms0);
        java.security.MessageDigest messageDigest20 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream21 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest22 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest20, inputStream21);
        java.security.MessageDigest messageDigest23 = org.apache.commons.codec.digest.DigestUtils.getDigest("$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1", messageDigest22);
        org.apache.commons.codec.net.URLCodec uRLCodec25 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet26 = null;
        byte[] byteArray28 = new byte[] { (byte) 100 };
        byte[] byteArray29 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet26, byteArray28);
        byte[] byteArray30 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray29);
        java.lang.String str31 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray29);
        byte[] byteArray32 = uRLCodec25.decode(byteArray29);
        byte[] byteArray33 = null;
        byte[] byteArray34 = uRLCodec25.decode(byteArray33);
        byte[] byteArray40 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str41 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray40);
        java.lang.String str43 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray40, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_44 = new org.apache.commons.codec.binary.Base16();
        boolean boolean46 = base16_44.isInAlphabet("AAAAAAA");
        byte[] byteArray50 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str52 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray50, true);
        java.lang.String str53 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray50);
        boolean boolean55 = base16_44.isInAlphabet(byteArray50, true);
        byte[] byteArray56 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray40, byteArray50);
        byte[] byteArray57 = uRLCodec25.encode(byteArray56);
        byte[] byteArray58 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest22, byteArray57);
        org.apache.commons.codec.digest.HmacUtils hmacUtils59 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, byteArray57);
        org.apache.commons.codec.net.URLCodec uRLCodec61 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet62 = null;
        byte[] byteArray64 = new byte[] { (byte) 100 };
        byte[] byteArray65 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet62, byteArray64);
        byte[] byteArray66 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray65);
        java.lang.String str67 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray65);
        byte[] byteArray68 = uRLCodec61.decode(byteArray65);
        byte[] byteArray74 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str75 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray74);
        java.lang.String str77 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray74, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str78 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray74);
        java.lang.String str79 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray74);
        java.lang.String str81 = org.apache.commons.codec.digest.Crypt.crypt(byteArray74, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec83 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet84 = null;
        byte[] byteArray86 = new byte[] { (byte) 100 };
        byte[] byteArray87 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet84, byteArray86);
        byte[] byteArray88 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray87);
        byte[] byteArray89 = uRLCodec83.encode(byteArray88);
        java.lang.String str90 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray74, byteArray88);
        byte[] byteArray91 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray88);
        byte[] byteArray92 = org.apache.commons.codec.digest.HmacUtils.hmacSha512(byteArray68, byteArray91);
        byte[] byteArray93 = hmacUtils59.hmac(byteArray92);
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5));
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str9, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertTrue("'" + boolean18 + "' != '" + true + "'", boolean18 == true);
        org.junit.Assert.assertNotNull(messageDigest20);
        org.junit.Assert.assertEquals(messageDigest20.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream21);
        org.junit.Assert.assertNotNull(messageDigest22);
        org.junit.Assert.assertEquals(messageDigest22.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest23);
        org.junit.Assert.assertEquals(messageDigest23.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[100]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[100]");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str31, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray32);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray32), "[100]");
        org.junit.Assert.assertNull(byteArray34);
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str41 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str41, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str43 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str43, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean46 + "' != '" + true + "'", boolean46 == true);
        org.junit.Assert.assertNotNull(byteArray50);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray50), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str52 + "' != '" + "ffffff" + "'", str52, "ffffff");
        org.junit.Assert.assertEquals("'" + str53 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str53, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean55 + "' != '" + false + "'", boolean55 == false);
        org.junit.Assert.assertNotNull(byteArray56);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray56), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray57);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray57), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
        org.junit.Assert.assertNotNull(byteArray58);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray58), "[89, 48, -113, 108, 117, -75, 18, 115, -46, 31, -95, -63, -99, 55, 109, 104, 50, 68, -65, -41, 63, -84, 13, 102, 29, -80, -127, -9, -97, 18, -127, -124, -100, 55, 76, -105, 24, -40, 49, 88, 5, 104, 0, -71, 81, 59, -44, 99, -61, -114, 90, 127, -32, 78, -24, -69, -6, -56, -59, 38, -65, 89, -13, -92]");
        org.junit.Assert.assertNotNull(byteArray64);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray64), "[100]");
        org.junit.Assert.assertNotNull(byteArray65);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray65), "[100]");
        org.junit.Assert.assertNotNull(byteArray66);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray66), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str67 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str67, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray68);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray68), "[100]");
        org.junit.Assert.assertNotNull(byteArray74);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray74), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str75 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str75, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str77 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str77, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str78 + "' != '" + "AAAAAAA" + "'", str78, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str79 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str79, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str81 + "' != '" + "0Acd8L3u4hVxI" + "'", str81, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray86);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray86), "[100]");
        org.junit.Assert.assertNotNull(byteArray87);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray87), "[100]");
        org.junit.Assert.assertNotNull(byteArray88);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray88), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray89);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray89), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str90 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str90, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray91);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray91), "[33, 101, -37, 32, -84, -63, -46, 45, 81, -94, -11, -68, -89, -14, 9, -75, -71, 31, 118, -100, 13, 48, -116, -5, 122, 42, -103, -34, -53, -98, -18, 32, -119, -119, 43, -69, -80, 12, 23, -61, -99, -12, 121, -19, -118, 115, -106, -34, 111, 109, 52, 72, -38, 120, 80, 35, 30, -85, 12, -100, -121, 27, 105, 82]");
        org.junit.Assert.assertNotNull(byteArray92);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray92), "[-66, 88, 18, 57, -83, -91, -63, -2, 12, 29, 4, -12, -28, -58, -74, 4, 111, 110, 117, 102, 82, -15, -21, 61, -99, -80, 61, -110, -126, -107, -70, 27, -82, 67, 46, -126, 24, 92, -17, -88, 25, -14, 122, 53, -95, 12, -73, 76, 9, 117, 65, -77, -100, 51, -38, 112, 98, -92, -121, 18, 60, -1, 75, -105]");
        org.junit.Assert.assertNotNull(byteArray93);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray93), "[-88, -4, -55, -110, -48, 72, -21, 74, 13, -38, 124, -84, 107, -107, -23, -112]");
    }

    @Test
    public void test2109() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2109");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray5);
        org.apache.commons.codec.binary.Base32 base32_14 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet15 = null;
        byte[] byteArray17 = new byte[] { (byte) 100 };
        byte[] byteArray18 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet15, byteArray17);
        byte[] byteArray19 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray18);
        boolean boolean21 = base32_14.isInAlphabet(byteArray19, false);
        byte[] byteArray23 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str24 = base32_14.encodeAsString(byteArray23);
        java.security.MessageDigest messageDigest25 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        java.security.MessageDigest messageDigest26 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream27 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest28 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest26, inputStream27);
        java.lang.String str29 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream27);
        byte[] byteArray30 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream27);
        java.security.MessageDigest messageDigest31 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest25, inputStream27);
        java.lang.String str32 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray23, inputStream27);
        byte[] byteArray33 = org.apache.commons.codec.digest.DigestUtils.md2(inputStream27);
        java.lang.String str34 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray5, inputStream27);
        java.math.BigInteger bigInteger35 = org.apache.commons.codec.binary.Base64.decodeInteger(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str11, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "\000\000\000\000\000" + "'", str12, "\000\000\000\000\000");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[100]");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[100]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean21 + "' != '" + false + "'", boolean21 == false);
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "ABUAA2IAEE======" + "'", str24, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(messageDigest25);
        org.junit.Assert.assertEquals(messageDigest25.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest26);
        org.junit.Assert.assertEquals(messageDigest26.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream27);
        org.junit.Assert.assertNotNull(messageDigest28);
        org.junit.Assert.assertEquals(messageDigest28.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str29, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(messageDigest31);
        org.junit.Assert.assertEquals(messageDigest31.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "ad1cae68ff9c689626df1f53ac8960047f9bd8ff" + "'", str32, "ad1cae68ff9c689626df1f53ac8960047f9bd8ff");
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[-125, 80, -27, -93, -30, 76, 21, 61, -14, 39, 92, -97, -128, 105, 39, 115]");
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d" + "'", str34, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
        org.junit.Assert.assertNotNull(bigInteger35);
    }

    @Test
    public void test2110() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2110");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex("SHA-512/256", "e0eb5e9075afc82312ac3087da9fc74f638df4d4a68460d1cef92aa6c5b9dad3abd69119903c85506b374249305e00c3");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "9e978ae12724db3c9e289dd3f1d48c8b" + "'", str2, "9e978ae12724db3c9e289dd3f1d48c8b");
    }

    @Test
    public void test2111() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2111");
        org.apache.commons.codec.digest.PureJavaCrc32 pureJavaCrc32_0 = new org.apache.commons.codec.digest.PureJavaCrc32();
        pureJavaCrc32_0.update(1);
        pureJavaCrc32_0.update(64);
        byte[] byteArray10 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray10);
        java.lang.String str13 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray10, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str14 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray10);
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray10);
        java.lang.String str17 = org.apache.commons.codec.digest.Crypt.crypt(byteArray10, "0A01640101");
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray10);
        // The following exception was thrown during execution in test generation
        try {
            pureJavaCrc32_0.update(byteArray10, 2057402559, 852759869);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 2057402559 out of bounds for length 5");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str11, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str13, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "AAAAAAA" + "'", str14, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str15, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "0Acd8L3u4hVxI" + "'", str17, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str18, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
    }

    @Test
    public void test2112() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2112");
        java.io.InputStream inputStream0 = java.io.InputStream.nullInputStream();
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream0);
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream0);
        byte[] byteArray3 = inputStream0.readAllBytes();
        byte[] byteArray4 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray3);
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(byteArray3);
        org.junit.Assert.assertNotNull(inputStream0);
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str1, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str2, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" + "'", str5, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    @Test
    public void test2113() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2113");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256("");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray1);
        char[] charArray3 = org.apache.commons.codec.binary.Hex.encodeHex(byteArray1);
        byte[] byteArray4 = org.apache.commons.codec.binary.BinaryCodec.fromAscii(charArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray4);
        java.lang.String str6 = org.apache.commons.codec.binary.BinaryCodec.toAsciiString(byteArray4);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-58, 114, -72, -47, -17, 86, -19, 40, -85, -121, -61, 98, 44, 81, 20, 6, -101, -35, 58, -41, -72, -7, 115, 116, -104, -48, -64, 30, -50, -16, -106, 122]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[32, -39, 31, 96, 101, 120, 98, 8, 87, 108, -31, 27, -25, -104, 91, 41, -2, 73, 60, -32, -6, 38, 39, 78, -25, 113, -31, -42, -88, 16, 47, 41]");
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[c, 6, 7, 2, b, 8, d, 1, e, f, 5, 6, e, d, 2, 8, a, b, 8, 7, c, 3, 6, 2, 2, c, 5, 1, 1, 4, 0, 6, 9, b, d, d, 3, a, d, 7, b, 8, f, 9, 7, 3, 7, 4, 9, 8, d, 0, c, 0, 1, e, c, e, f, 0, 9, 6, 7, a]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[0, 2, 0, 0, 24, 0, 0, 1]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[1, -114, 101, 58, 114, 28, -116, 34, 89, -93, -123, 65, -34, 2, -6, -60, -36, 20, -13, 92, 11, 90, 42, -21, 26, 6, 57, 28]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "0000000100000000000000000001100000000000000000000000001000000000" + "'", str6, "0000000100000000000000000001100000000000000000000000001000000000");
    }

    @Test
    public void test2114() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2114");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder0.setRuleType(ruleType1);
        org.apache.commons.codec.language.bm.NameType nameType3 = beiderMorseEncoder0.getNameType();
        java.lang.String str4 = nameType3.getName();
        org.apache.commons.codec.language.bm.Languages languages5 = org.apache.commons.codec.language.bm.Languages.getInstance(nameType3);
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType3 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType3.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "gen" + "'", str4, "gen");
        org.junit.Assert.assertNotNull(languages5);
    }

    @Test
    public void test2115() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2115");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[97, 55, 102, 102, 99, 54, 102, 56, 98, 102, 49, 101, 100, 55, 54, 54, 53, 49, 99, 49, 52, 55, 53, 54, 97, 48, 54, 49, 100, 54, 54, 50, 102, 53, 56, 48, 102, 102, 52, 100, 101, 52, 51, 98, 52, 57, 102, 97, 56, 50, 100, 56, 48, 97, 52, 98, 56, 48, 102, 56, 52, 51, 52, 97]");
    }

    @Test
    public void test2116() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2116");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        byte[] byteArray8 = uRLCodec1.decode(byteArray5);
        byte[] byteArray9 = null;
        byte[] byteArray10 = uRLCodec1.decode(byteArray9);
        byte[] byteArray13 = org.apache.commons.codec.digest.HmacUtils.hmacMd5("UTF-8", "$1$UYtF..0A$qlvzexZps/99jmTbfJRm11");
        byte[] byteArray15 = org.apache.commons.codec.binary.StringUtils.getBytesUsAscii("XWUWENAPMNXDP2MJAOKTSRGP4IWY6HXWWVSOLPVEJJLV6JIAMSHTLYUG66TNXOZG4UREMFI2NTIFL3LTOALTUKJHVFUD6JIUHBCP7KA=3D");
        byte[] byteArray16 = org.apache.commons.codec.digest.DigestUtils.sha512(byteArray15);
        java.lang.String str17 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, byteArray15);
        byte[] byteArray18 = uRLCodec1.encode(byteArray13);
        boolean boolean19 = org.apache.commons.codec.binary.Base64.isBase64(byteArray13);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str7, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
        org.junit.Assert.assertNull(byteArray10);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-22, 0, -46, 104, 69, -9, -124, -117, -95, 77, -10, -97, -56, 105, -38, 29]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[88, 87, 85, 87, 69, 78, 65, 80, 77, 78, 88, 68, 80, 50, 77, 74, 65, 79, 75, 84, 83, 82, 71, 80, 52, 73, 87, 89, 54, 72, 88, 87, 87, 86, 83, 79, 76, 80, 86, 69, 74, 74, 76, 86, 54, 74, 73, 65, 77, 83, 72, 84, 76, 89, 85, 71, 54, 54, 84, 78, 88, 79, 90, 71, 52, 85, 82, 69, 77, 70, 73, 50, 78, 84, 73, 70, 76, 51, 76, 84, 79, 65, 76, 84, 85, 75, 74, 72, 86, 70, 85, 68, 54, 74, 73, 85, 72, 66, 67, 80, 55, 75, 65, 61, 51, 68]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[-48, -127, 78, 47, 13, 54, 77, -114, 6, -43, -78, -19, -59, -90, 41, 91, 55, -43, 107, 101, 21, -123, 87, -111, 29, 59, 4, -119, 60, 13, -42, 95, -97, 4, 81, 103, 78, -111, -86, -76, 56, -84, 97, -59, -103, -75, 98, 60, -91, 63, 53, 18, 51, 56, -126, -117, 36, -70, -47, 58, 43, 24, 60, -68]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "58cfd93fbeaefa462533f27403c2ed80e077aef9ef528d9557625019eb3e38fc13bd23a7b2f992c3d9ac159dc63448d8e47076027af3c0ba75030f7ea0d76877" + "'", str17, "58cfd93fbeaefa462533f27403c2ed80e077aef9ef528d9557625019eb3e38fc13bd23a7b2f992c3d9ac159dc63448d8e47076027af3c0ba75030f7ea0d76877");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[37, 69, 65, 37, 48, 48, 37, 68, 50, 104, 69, 37, 70, 55, 37, 56, 52, 37, 56, 66, 37, 65, 49, 77, 37, 70, 54, 37, 57, 70, 37, 67, 56, 105, 37, 68, 65, 37, 49, 68]");
        org.junit.Assert.assertTrue("'" + boolean19 + "' != '" + false + "'", boolean19 == false);
    }

    @Test
    public void test2117() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2117");
        org.apache.commons.codec.EncoderException encoderException1 = new org.apache.commons.codec.EncoderException("$apr1$000000$ou.zfWkkW561mymARAgg2/");
        java.lang.Throwable[] throwableArray2 = encoderException1.getSuppressed();
        org.junit.Assert.assertNotNull(throwableArray2);
    }

    @Test
    public void test2118() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2118");
        org.apache.commons.codec.language.MatchRatingApproachEncoder matchRatingApproachEncoder0 = new org.apache.commons.codec.language.MatchRatingApproachEncoder();
        java.lang.String str2 = matchRatingApproachEncoder0.encode("e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        java.lang.String str4 = matchRatingApproachEncoder0.encode("D0");
        boolean boolean7 = matchRatingApproachEncoder0.isEncodeEquals("acba47930de7dea5109181bfc00014d106f31259", "4c98f32a81be34128784b1e12b12b6d0067344e3e7697e56b3132f7a0ce68b473defef83edcaf80923730064ca2318078fbb9fa3444ce5ddcda20d72d173ac1d");
        java.lang.String str9 = matchRatingApproachEncoder0.encode("c82c8ab22f3a62af4973396a2ad745b3");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "E99B98" + "'", str2, "E99B98");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "D0" + "'", str4, "D0");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "C825B3" + "'", str9, "C825B3");
    }

    @Test
    public void test2119() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2119");
        java.lang.Throwable throwable1 = null;
        org.apache.commons.codec.EncoderException encoderException2 = new org.apache.commons.codec.EncoderException("66/bcRxcmsqC.", throwable1);
        org.apache.commons.codec.EncoderException encoderException3 = new org.apache.commons.codec.EncoderException(throwable1);
    }

    @Test
    public void test2120() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2120");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.SEPHARDIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        java.lang.String str2 = nameType0.getName();
        org.apache.commons.codec.language.bm.RuleType ruleType3 = org.apache.commons.codec.language.bm.RuleType.APPROX;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine6 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType3, false, (-1534769883));
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.SEPHARDIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.SEPHARDIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "sep" + "'", str2, "sep");
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.APPROX + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.APPROX));
    }

    @Test
    public void test2121() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2121");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = uRLCodec1.encode(byteArray6);
        long[] longArray11 = org.apache.commons.codec.digest.MurmurHash3.hash128(byteArray6, (int) (short) 0, (int) (byte) 0, (-2042891860));
        org.apache.commons.codec.digest.Blake3 blake3_12 = org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction(byteArray6);
        blake3_12.reset();
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertNotNull(longArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(longArray11), "[6932822957065537513, -327338885100050123]");
        org.junit.Assert.assertNotNull(blake3_12);
    }

    @Test
    public void test2122() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2122");
        org.apache.commons.codec.binary.Hex hex0 = new org.apache.commons.codec.binary.Hex();
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer3 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, byteBuffer3);
        char[] charArray6 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer3, true);
        byte[] byteArray7 = hex0.decode(byteBuffer3);
        java.lang.Object obj9 = hex0.encode((java.lang.Object) "HmacMD5");
        byte[] byteArray12 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray13 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray12);
        java.io.InputStream inputStream14 = java.io.InputStream.nullInputStream();
        java.lang.String str15 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, inputStream14);
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream16);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream16);
        java.lang.String str19 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, inputStream16);
        byte[] byteArray21 = inputStream16.readNBytes((int) ' ');
        byte[] byteArray23 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray21, true);
        java.lang.String str24 = org.apache.commons.codec.digest.Crypt.crypt(byteArray23);
        org.apache.commons.codec.CodecPolicy codecPolicy27 = org.apache.commons.codec.CodecPolicy.LENIENT;
        org.apache.commons.codec.binary.Base16 base16_28 = new org.apache.commons.codec.binary.Base16(false, codecPolicy27);
        org.apache.commons.codec.binary.Base64 base64_29 = new org.apache.commons.codec.binary.Base64((int) (short) 10, byteArray23, true, codecPolicy27);
        byte[] byteArray30 = hex0.encode(byteArray23);
        java.security.MessageDigest messageDigest31 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils32 = new org.apache.commons.codec.digest.DigestUtils(messageDigest31);
        java.io.OutputStream outputStream33 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_35 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream37 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream33, (org.apache.commons.codec.binary.BaseNCodec) base16_35, false);
        byte[] byteArray40 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str41 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray40);
        long long42 = base16_35.getEncodedLength(byteArray40);
        byte[] byteArray43 = digestUtils32.digest(byteArray40);
        java.security.MessageDigest messageDigest44 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils45 = new org.apache.commons.codec.digest.DigestUtils(messageDigest44);
        java.security.MessageDigest messageDigest46 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer48 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest49 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest46, byteBuffer48);
        char[] charArray51 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer48, true);
        java.lang.String str52 = digestUtils45.digestAsHex(byteBuffer48);
        byte[] byteArray53 = digestUtils32.digest(byteBuffer48);
        byte[] byteArray54 = hex0.encode(byteBuffer48);
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer3);
        org.junit.Assert.assertNotNull(messageDigest4);
        org.junit.Assert.assertEquals(messageDigest4.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray6);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray6), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray6), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray6), "[]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertNotNull(obj9);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream14);
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str15, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str17, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str18, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str19, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[]");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[]");
// flaky:         org.junit.Assert.assertEquals("'" + str24 + "' != '" + "$6$d.RD2u1p$7ZUiRMP.lyoUwqT.OfItv1lhFbosIZArQPeBPiG3NqY8oH2Tv0pQzjlCmNfaoJ2BE8OwJse/jTNMF0YDMN3Qv." + "'", str24, "$6$d.RD2u1p$7ZUiRMP.lyoUwqT.OfItv1lhFbosIZArQPeBPiG3NqY8oH2Tv0pQzjlCmNfaoJ2BE8OwJse/jTNMF0YDMN3Qv.");
        org.junit.Assert.assertTrue("'" + codecPolicy27 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy27.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[]");
        org.junit.Assert.assertNotNull(messageDigest31);
        org.junit.Assert.assertEquals(messageDigest31.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(outputStream33);
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str41 + "' != '" + "\000\ufffd" + "'", str41, "\000\ufffd");
        org.junit.Assert.assertTrue("'" + long42 + "' != '" + 4L + "'", long42 == 4L);
        org.junit.Assert.assertNotNull(byteArray43);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray43), "[118, 16, 18, -102, -37, -99, -101, 93, -121, -6, 112, 76, 20, -78, -89, -111, 104, -101, 56, 39, -120, -81, 72, -106, 82, 11, 76, 29, 47, -108, 35, -72, -58, -24, -103, 19, -66, 1, 77, -23, 89, -100, 93, 116, 115, 18, -91, -9]");
        org.junit.Assert.assertNotNull(messageDigest44);
        org.junit.Assert.assertEquals(messageDigest44.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest46);
        org.junit.Assert.assertEquals(messageDigest46.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer48);
        org.junit.Assert.assertNotNull(messageDigest49);
        org.junit.Assert.assertEquals(messageDigest49.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(charArray51);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray51), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray51), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray51), "[]");
        org.junit.Assert.assertEquals("'" + str52 + "' != '" + "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" + "'", str52, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
        org.junit.Assert.assertNotNull(byteArray53);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray53), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(byteArray54);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray54), "[]");
    }

    @Test
    public void test2123() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2123");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms1 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        javax.crypto.Mac mac7 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms1, byteArray6);
        byte[] byteArray13 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray13);
        java.lang.String str16 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray13, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str17 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray13);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray13);
        java.lang.String str19 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray13);
        javax.crypto.Mac mac20 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms1, byteArray13);
        org.apache.commons.codec.binary.Base32 base32_22 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet23 = null;
        byte[] byteArray25 = new byte[] { (byte) 100 };
        byte[] byteArray26 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet23, byteArray25);
        byte[] byteArray27 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray26);
        boolean boolean29 = base32_22.isInAlphabet(byteArray27, false);
        byte[] byteArray31 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str32 = base32_22.encodeAsString(byteArray31);
        org.apache.commons.codec.digest.HmacUtils hmacUtils33 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms1, byteArray31);
        java.lang.String str35 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray31, "$1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.");
        org.apache.commons.codec.binary.Base64 base64_37 = new org.apache.commons.codec.binary.Base64((-64519185), byteArray31, false);
        boolean boolean38 = base64_37.isUrlSafe();
        org.apache.commons.codec.CodecPolicy codecPolicy39 = base64_37.getCodecPolicy();
        org.junit.Assert.assertTrue("'" + hmacAlgorithms1 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms1.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac7);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str14, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str16, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "AAAAAAA" + "'", str17, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str18, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str19, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac20);
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[100]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[100]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean29 + "' != '" + false + "'", boolean29 == false);
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "ABUAA2IAEE======" + "'", str32, "ABUAA2IAEE======");
        org.junit.Assert.assertEquals("'" + str35 + "' != '" + "$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3." + "'", str35, "$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3.");
        org.junit.Assert.assertTrue("'" + boolean38 + "' != '" + false + "'", boolean38 == false);
        org.junit.Assert.assertTrue("'" + codecPolicy39 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy39.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test2124() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2124");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray8, false);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, byteArray8);
        byte[] byteArray14 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray15 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray14);
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        java.lang.String str17 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray15, inputStream16);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream18 = new org.apache.commons.codec.binary.Base64InputStream(inputStream16);
        byte[] byteArray19 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray8, (java.io.InputStream) base64InputStream18);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex((java.io.InputStream) base64InputStream18);
        long long22 = base64InputStream18.skip((long) 64);
        base64InputStream18.mark(1787795390);
        boolean boolean25 = base64InputStream18.isStrictDecoding();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream27 = new org.apache.commons.codec.binary.Base32InputStream((java.io.InputStream) base64InputStream18, false);
        base64InputStream18.mark(1595328082);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0A01640101" + "'", str11, "0A01640101");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str12, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str17, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[2, 34, -90, -86, 24, -114, 46, 116, -89, 122, -11, -103, 109, 29, -113, 57, -115, -50, -121, -67, 99, -35, 44, 88, -108, 52, 45, 68, -1, -123, 62, -43, 37, -26, -55, -24, 47, -94, 118, -68, 91, -39, 125, -89, 38, -102, -107, 112]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" + "'", str20, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        org.junit.Assert.assertTrue("'" + long22 + "' != '" + 0L + "'", long22 == 0L);
        org.junit.Assert.assertTrue("'" + boolean25 + "' != '" + false + "'", boolean25 == false);
    }

    @Test
    public void test2125() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2125");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = new org.apache.commons.codec.language.DoubleMetaphone();
        java.lang.String str2 = doubleMetaphone0.doubleMetaphone("kBAwnYFpJm7aQ");
        org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult4 = doubleMetaphone0.new DoubleMetaphoneResult(686869806);
        doubleMetaphoneResult4.appendAlternate('4');
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "KPNF" + "'", str2, "KPNF");
    }

    @Test
    public void test2126() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2126");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        byte[] byteArray3 = digestUtils1.digest("000000");
        java.io.File file4 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = digestUtils1.digestAsHex(file4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-88, -42, -80, 29, 31, -10, 45, 62, -11, -91, -46, -43, 53, 73, -34, 84, 112, 53, 75, 16, 63, 41, -41, -12, -84, 58, -45, 89, -52, 51, -89, -67, -86, -127, 98, 92, -126, 40, 94, 76, 56, -43, 105, 69, -115, -59, 104, 41]");
    }

    @Test
    public void test2127() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2127");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream1);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_256(inputStream1);
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(byteArray4);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str3, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-89, -1, -58, -8, -65, 30, -41, 102, 81, -63, 71, 86, -96, 97, -42, 98, -11, -128, -1, 77, -28, 59, 73, -6, -126, -40, 10, 75, -128, -8, 67, 74]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "faa9e0a482a1d15f1d36de8a25d869da3dc6b416fab1efeb3cbf1fd9fe7fea484c85256485e2905b3deab9ded22b4bd29c6d9f1576c280f4a2a5878fd70c0f1a" + "'", str5, "faa9e0a482a1d15f1d36de8a25d869da3dc6b416fab1efeb3cbf1fd9fe7fea484c85256485e2905b3deab9ded22b4bd29c6d9f1576c280f4a2a5878fd70c0f1a");
    }

    @Test
    public void test2128() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2128");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        org.apache.commons.codec.language.bm.Lang lang6 = phoneticEngine4.getLang();
        int int7 = phoneticEngine4.getMaxPhonemes();
        int int8 = phoneticEngine4.getMaxPhonemes();
        int int9 = phoneticEngine4.getMaxPhonemes();
        int int10 = phoneticEngine4.getMaxPhonemes();
        int int11 = phoneticEngine4.getMaxPhonemes();
        org.junit.Assert.assertNull(ruleType5);
        org.junit.Assert.assertNull(lang6);
        org.junit.Assert.assertTrue("'" + int7 + "' != '" + (-1) + "'", int7 == (-1));
        org.junit.Assert.assertTrue("'" + int8 + "' != '" + (-1) + "'", int8 == (-1));
        org.junit.Assert.assertTrue("'" + int9 + "' != '" + (-1) + "'", int9 == (-1));
        org.junit.Assert.assertTrue("'" + int10 + "' != '" + (-1) + "'", int10 == (-1));
        org.junit.Assert.assertTrue("'" + int11 + "' != '" + (-1) + "'", int11 == (-1));
    }

    @Test
    public void test2129() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2129");
        org.apache.commons.codec.language.Soundex soundex1 = new org.apache.commons.codec.language.Soundex("63a1f2e3e54d95691b19fe5345d3a8328ed2219d984ca4db3695f023c8b4db19");
    }

    @Test
    public void test2130() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2130");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("$6$D5MbQO/U$G04bgWM6O9qwY.HBx93TRiq9s/I8tv0OgyDmQARAuiXo6hkq6fbNEWrrppGhWkljYuuiWw8NgTpP6JB9Vtwxr0");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "5d1d1c8b26f130296abdbb2aed0946d5c2441b7497f19e2984cbcbb3" + "'", str1, "5d1d1c8b26f130296abdbb2aed0946d5c2441b7497f19e2984cbcbb3");
    }

    @Test
    public void test2131() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2131");
        int int3 = org.apache.commons.codec.digest.MurmurHash3.hash32(4292301682L, (long) (short) 1, (-1612190696));
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + 635491687 + "'", int3 == 635491687);
    }

    @Test
    public void test2132() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2132");
        org.apache.commons.codec.binary.Base64 base64_2 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy3 = base64_2.getCodecPolicy();
        org.apache.commons.codec.binary.Base16 base16_4 = new org.apache.commons.codec.binary.Base16(true, codecPolicy3);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha512_256("663b90c899fa25a111067be0c22ffc64dcf581c2");
        long long7 = org.apache.commons.codec.digest.MurmurHash3.hash64(byteArray6);
        java.lang.String str8 = base16_4.encodeAsString(byteArray6);
        org.junit.Assert.assertTrue("'" + codecPolicy3 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy3.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-120, 74, 80, 67, 126, -7, 88, -59, -93, -11, 8, 116, -113, -126, 0, -67, -35, 70, -7, 63, -27, -66, 34, -13, 38, 6, -125, -101, -4, 88, 60, 31]");
        org.junit.Assert.assertTrue("'" + long7 + "' != '" + (-5308976831970353554L) + "'", long7 == (-5308976831970353554L));
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "884a50437ef958c5a3f508748f8200bddd46f93fe5be22f32606839bfc583c1f" + "'", str8, "884a50437ef958c5a3f508748f8200bddd46f93fe5be22f32606839bfc583c1f");
    }

    @Test
    public void test2133() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2133");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            int int14 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray5, 2057402559, (int) (short) 100, (int) (short) 0);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 2057402559 out of bounds for length 5");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
    }

    @Test
    public void test2134() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2134");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator3 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) soundex2);
        org.apache.commons.codec.language.bm.NameType nameType5 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType6 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet7 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap8 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType5, ruleType6, languageSet7);
        int int9 = stringEncoderComparator3.compare((java.lang.Object) "0Acd8L3u4hVxI", (java.lang.Object) ruleType6);
        java.lang.Object obj10 = null;
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.sha384("$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30");
        int int13 = stringEncoderComparator3.compare(obj10, (java.lang.Object) byteArray12);
        int int14 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray12);
        org.junit.Assert.assertTrue("'" + nameType5 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType5.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType6 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType6.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet7);
        org.junit.Assert.assertNotNull(strMap8);
        org.junit.Assert.assertTrue("'" + int9 + "' != '" + 0 + "'", int9 == 0);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[-52, 110, 77, -11, 61, -50, -33, 45, 79, 25, 89, -18, 82, 46, -127, -81, 25, -118, -11, 81, -37, 127, -92, 107, 17, -71, -36, 112, -109, -117, 62, 15, 89, -23, 70, -74, 70, -18, -99, 6, 108, 32, 10, -123, -125, -32, 14, -82]");
        org.junit.Assert.assertTrue("'" + int13 + "' != '" + 0 + "'", int13 == 0);
        org.junit.Assert.assertTrue("'" + int14 + "' != '" + 1571438259 + "'", int14 == 1571438259);
    }

    @Test
    public void test2135() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2135");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.nio.charset.Charset charset16 = org.apache.commons.codec.Charsets.UTF_8;
        java.lang.String str17 = quotedPrintableCodec1.decode("663b90c899fa25a111067be0c22ffc64dcf581c2", charset16);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str20 = quotedPrintableCodec1.encode("FDAFAD", "4");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: 4");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str8, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str10, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "AAAAAAA" + "'", str11, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str12, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str13, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj14);
        org.junit.Assert.assertNotNull(charset16);
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "663b90c899fa25a111067be0c22ffc64dcf581c2" + "'", str17, "663b90c899fa25a111067be0c22ffc64dcf581c2");
    }

    @Test
    public void test2136() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2136");
        java.lang.String[] strArray39 = new java.lang.String[] { "ffffff", "663b90c899fa25a111067be0c22ffc64dcf581c2", "SHA-224", "0Acd8L3u4hVxI", "UTF-16LE", "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "2ef0725975afd171e9cb76444b4969c3", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "ffffff", "6IiiRyxmjcARw", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "0A01640101", "2ef0725975afd171e9cb76444b4969c3", "663b90c899fa25a111067be0c22ffc64dcf581c2", "", "ffffff", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", "6IiiRyxmjcARw", "663b90c899fa25a111067be0c22ffc64dcf581c2", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "MD2", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "99448658175a0534e08dbca1fe67b58231a53eec", "0A01640101", "0A01640101", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "SHA3-256", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107", "", "663b90c899fa25a111067be0c22ffc64dcf581c2", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" };
        java.util.LinkedHashSet<java.lang.String> strSet40 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean41 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet40, strArray39);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet42 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet40);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet43 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet40);
        boolean boolean44 = languageSet43.isEmpty();
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme45 = new org.apache.commons.codec.language.bm.Rule.Phoneme((java.lang.CharSequence) "$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/", languageSet43);
        java.lang.String[] strArray85 = new java.lang.String[] { "ffffff", "663b90c899fa25a111067be0c22ffc64dcf581c2", "SHA-224", "0Acd8L3u4hVxI", "UTF-16LE", "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "2ef0725975afd171e9cb76444b4969c3", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "ffffff", "6IiiRyxmjcARw", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "0A01640101", "2ef0725975afd171e9cb76444b4969c3", "663b90c899fa25a111067be0c22ffc64dcf581c2", "", "ffffff", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", "6IiiRyxmjcARw", "663b90c899fa25a111067be0c22ffc64dcf581c2", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "MD2", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "99448658175a0534e08dbca1fe67b58231a53eec", "0A01640101", "0A01640101", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "SHA3-256", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107", "", "663b90c899fa25a111067be0c22ffc64dcf581c2", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" };
        java.util.LinkedHashSet<java.lang.String> strSet86 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean87 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet86, strArray85);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet88 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet86);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet89 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet86);
        boolean boolean90 = languageSet89.isEmpty();
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme91 = new org.apache.commons.codec.language.bm.Rule.Phoneme((java.lang.CharSequence) "$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/", languageSet89);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet92 = phoneme91.getLanguages();
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme93 = new org.apache.commons.codec.language.bm.Rule.Phoneme(phoneme45, phoneme91);
        org.junit.Assert.assertNotNull(strArray39);
        org.junit.Assert.assertTrue("'" + boolean41 + "' != '" + true + "'", boolean41 == true);
        org.junit.Assert.assertNotNull(languageSet42);
        org.junit.Assert.assertNotNull(languageSet43);
        org.junit.Assert.assertTrue("'" + boolean44 + "' != '" + false + "'", boolean44 == false);
        org.junit.Assert.assertNotNull(strArray85);
        org.junit.Assert.assertTrue("'" + boolean87 + "' != '" + true + "'", boolean87 == true);
        org.junit.Assert.assertNotNull(languageSet88);
        org.junit.Assert.assertNotNull(languageSet89);
        org.junit.Assert.assertTrue("'" + boolean90 + "' != '" + false + "'", boolean90 == false);
        org.junit.Assert.assertNotNull(languageSet92);
    }

    @Test
    public void test2137() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2137");
        org.apache.commons.codec.binary.Base64 base64_1 = new org.apache.commons.codec.binary.Base64((-488200341));
    }

    @Test
    public void test2138() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2138");
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray3 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        java.io.InputStream inputStream4 = java.io.InputStream.nullInputStream();
        java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray3, inputStream4);
        java.io.InputStream inputStream6 = java.io.InputStream.nullInputStream();
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream6);
        java.lang.String str9 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray3, inputStream6);
        byte[] byteArray11 = inputStream6.readNBytes((int) ' ');
        byte[] byteArray13 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray11, true);
        java.lang.String str14 = org.apache.commons.codec.digest.Crypt.crypt(byteArray13);
        org.apache.commons.codec.CodecPolicy codecPolicy17 = org.apache.commons.codec.CodecPolicy.LENIENT;
        org.apache.commons.codec.binary.Base16 base16_18 = new org.apache.commons.codec.binary.Base16(false, codecPolicy17);
        org.apache.commons.codec.binary.Base64 base64_19 = new org.apache.commons.codec.binary.Base64((int) (short) 10, byteArray13, true, codecPolicy17);
        org.apache.commons.codec.net.URLCodec uRLCodec21 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray25 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str27 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray25, true);
        java.lang.String str28 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray25);
        byte[] byteArray29 = uRLCodec21.decode(byteArray25);
        char[] charArray30 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray29);
        long long31 = base64_19.getEncodedLength(byteArray29);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream4);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str5, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream6);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str7, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str8, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str9, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[]");
// flaky:         org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$6$ou4Hoyel$6PjfuI.g42qV6GzQWE1jDQs7KASTa56lp1Vkd.UVj/gA//EN7v5YJmCn66sP44Xi38sIo8Gfrmul3LxgWovPI." + "'", str14, "$6$ou4Hoyel$6PjfuI.g42qV6GzQWE1jDQs7KASTa56lp1Vkd.UVj/gA//EN7v5YJmCn66sP44Xi38sIo8Gfrmul3LxgWovPI.");
        org.junit.Assert.assertTrue("'" + codecPolicy17 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy17.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "ffffff" + "'", str27, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str28 + "' != '" + "$1$RxmyWFaR$ruiDsiFNui/HiJgpm3Wpj/" + "'", str28, "$1$RxmyWFaR$ruiDsiFNui/HiJgpm3Wpj/");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[0, 0, 0]");
        org.junit.Assert.assertNotNull(charArray30);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray30), "000000000000000000000000");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray30), "000000000000000000000000");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray30), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertTrue("'" + long31 + "' != '" + 4L + "'", long31 == 4L);
    }

    @Test
    public void test2139() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2139");
        org.apache.commons.codec.language.DaitchMokotoffSoundex daitchMokotoffSoundex1 = new org.apache.commons.codec.language.DaitchMokotoffSoundex(false);
        java.lang.String str3 = daitchMokotoffSoundex1.encode("SHA-512/256");
        java.lang.String str5 = daitchMokotoffSoundex1.soundex("e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        java.lang.String str7 = daitchMokotoffSoundex1.encode("FTPF");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "400000" + "'", str3, "400000");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "073743|073753" + "'", str5, "073743|073753");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "737000" + "'", str7, "737000");
    }

    @Test
    public void test2140() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2140");
        org.apache.commons.codec.binary.Base16 base16_0 = new org.apache.commons.codec.binary.Base16();
        boolean boolean2 = base16_0.isInAlphabet("AAAAAAA");
        boolean boolean4 = base16_0.isInAlphabet((byte) 1);
        java.util.BitSet bitSet5 = null;
        byte[] byteArray11 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray11);
        java.lang.String str14 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray11, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str15 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray11);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray11);
        java.lang.String str18 = org.apache.commons.codec.digest.Crypt.crypt(byteArray11, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec20 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet21 = null;
        byte[] byteArray23 = new byte[] { (byte) 100 };
        byte[] byteArray24 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet21, byteArray23);
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray24);
        byte[] byteArray26 = uRLCodec20.encode(byteArray25);
        java.lang.String str27 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray11, byteArray25);
        byte[] byteArray28 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray11);
        byte[] byteArray29 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet5, byteArray28);
        java.lang.String str30 = base16_0.encodeAsString(byteArray28);
        byte[] byteArray31 = org.apache.commons.codec.digest.DigestUtils.sha256(byteArray28);
        javax.crypto.Mac mac32 = org.apache.commons.codec.digest.HmacUtils.getHmacMd5(byteArray31);
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + true + "'", boolean2 == true);
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str12, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str14, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "AAAAAAA" + "'", str15, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str16, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "0Acd8L3u4hVxI" + "'", str18, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[100]");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[100]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str27, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48]");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "0000000000" + "'", str30, "0000000000");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[-120, 85, 80, -118, -83, -31, 110, -59, 115, -46, 30, 106, 72, 93, -3, 10, 118, 36, 8, 92, 26, 20, -75, -20, -35, 100, -123, -34, 12, 104, 57, -92]");
        org.junit.Assert.assertNotNull(mac32);
    }

    @Test
    public void test2141() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2141");
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str6 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray4, true);
        org.apache.commons.codec.CodecPolicy codecPolicy8 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base64 base64_9 = new org.apache.commons.codec.binary.Base64((int) (byte) 0, byteArray4, true, codecPolicy8);
        org.apache.commons.codec.CodecPolicy codecPolicy10 = base64_9.getCodecPolicy();
        org.apache.commons.codec.language.Soundex soundex13 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator14 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) soundex13);
        int int17 = soundex13.difference("ad1cae68ff9c689626df1f53ac8960047f9bd8ff", "I6ae");
        java.lang.String str19 = soundex13.encode("ab58a8ecd617b254b3bfc56ff14d5a91d6b42d26a5b0a13d1caa38fbca4cef66");
        java.lang.String str21 = soundex13.encode("000000");
        java.lang.Object obj22 = base64_9.decode((java.lang.Object) str21);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "ffffff" + "'", str6, "ffffff");
        org.junit.Assert.assertTrue("'" + codecPolicy8 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy8.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertTrue("'" + codecPolicy10 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy10.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertTrue("'" + int17 + "' != '" + 0 + "'", int17 == 0);
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "A3d2" + "'", str19, "A3d2");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "" + "'", str21, "");
        org.junit.Assert.assertNotNull(obj22);
    }

    @Test
    public void test2142() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2142");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        byte[] byteArray12 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray12);
        java.lang.String str15 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray12, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str16 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray12);
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray12);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray12);
        javax.crypto.Mac mac19 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray12);
        org.apache.commons.codec.binary.Base32 base32_21 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet22 = null;
        byte[] byteArray24 = new byte[] { (byte) 100 };
        byte[] byteArray25 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet22, byteArray24);
        byte[] byteArray26 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray25);
        boolean boolean28 = base32_21.isInAlphabet(byteArray26, false);
        byte[] byteArray30 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str31 = base32_21.encodeAsString(byteArray30);
        org.apache.commons.codec.digest.HmacUtils hmacUtils32 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, byteArray30);
        java.nio.ByteBuffer byteBuffer34 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        char[] charArray35 = org.apache.commons.codec.binary.Hex.encodeHex(byteBuffer34);
        java.lang.String str36 = hmacUtils32.hmacHex(byteBuffer34);
        byte[] byteArray37 = null;
        byte[] byteArray38 = hmacUtils32.hmac(byteArray37);
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str13, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str15, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "AAAAAAA" + "'", str16, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str17, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str18, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac19);
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[100]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[100]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean28 + "' != '" + false + "'", boolean28 == false);
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "ABUAA2IAEE======" + "'", str31, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(byteBuffer34);
        org.junit.Assert.assertNotNull(charArray35);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray35), "5348412d3531322f323536");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray35), "5348412d3531322f323536");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray35), "[5, 3, 4, 8, 4, 1, 2, d, 3, 5, 3, 1, 3, 2, 2, f, 3, 2, 3, 5, 3, 6]");
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "f313dfed06ae19881e8ee3eed2feec0f97fb6ce0f011438c7f854a5f" + "'", str36, "f313dfed06ae19881e8ee3eed2feec0f97fb6ce0f011438c7f854a5f");
        org.junit.Assert.assertNotNull(byteArray38);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray38), "[-13, 19, -33, -19, 6, -82, 25, -120, 30, -114, -29, -18, -46, -2, -20, 15, -105, -5, 108, -32, -16, 17, 67, -116, 127, -123, 74, 95]");
    }

    @Test
    public void test2143() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2143");
        org.apache.commons.codec.language.Nysiis nysiis1 = new org.apache.commons.codec.language.Nysiis(true);
        boolean boolean2 = nysiis1.isStrict();
        boolean boolean3 = nysiis1.isStrict();
        java.lang.String str5 = nysiis1.encode("rules");
        java.nio.charset.Charset charset6 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy7 = null;
        org.apache.commons.codec.net.BCodec bCodec8 = new org.apache.commons.codec.net.BCodec(charset6, codecPolicy7);
        org.apache.commons.codec.net.QCodec qCodec9 = new org.apache.commons.codec.net.QCodec(charset6);
        java.nio.charset.Charset charset10 = qCodec9.getCharset();
        java.nio.charset.Charset charset11 = qCodec9.getCharset();
        java.lang.Object obj12 = null;
        java.lang.Object obj13 = qCodec9.encode(obj12);
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec16 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray22 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str23 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray22);
        java.lang.String str25 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray22, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str26 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray22);
        java.lang.String str27 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray22);
        java.lang.String str28 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray22);
        java.lang.Object obj29 = quotedPrintableCodec16.decode((java.lang.Object) byteArray22);
        java.lang.String str30 = quotedPrintableCodec16.getDefaultCharset();
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec33 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray39 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str40 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray39);
        java.lang.String str42 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray39, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str43 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray39);
        java.lang.String str44 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray39);
        java.lang.String str45 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray39);
        java.lang.Object obj46 = quotedPrintableCodec33.decode((java.lang.Object) byteArray39);
        java.lang.String str47 = quotedPrintableCodec33.getDefaultCharset();
        java.lang.String str48 = quotedPrintableCodec33.getDefaultCharset();
        java.lang.String str50 = quotedPrintableCodec33.decode("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.nio.charset.Charset charset52 = org.apache.commons.codec.Charsets.UTF_16BE;
        java.lang.String str53 = quotedPrintableCodec33.encode("00001010000011010110100001000001010100010110000101000001011001110100011101000001", charset52);
        java.lang.String str54 = quotedPrintableCodec16.decode("$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/", charset52);
        java.lang.String str55 = qCodec9.encode("$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30", charset52);
        java.lang.Object obj56 = nysiis1.encode((java.lang.Object) "$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30");
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + true + "'", boolean2 == true);
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + true + "'", boolean3 == true);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "RAL" + "'", str5, "RAL");
        org.junit.Assert.assertNotNull(charset6);
        org.junit.Assert.assertNotNull(charset10);
        org.junit.Assert.assertNotNull(charset11);
        org.junit.Assert.assertNull(obj13);
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str23, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str25, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "AAAAAAA" + "'", str26, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str27, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str28 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str28, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj29);
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "UTF-8" + "'", str30, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str40 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str40, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str42 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str42, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str43 + "' != '" + "AAAAAAA" + "'", str43, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str44 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str44, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str45 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str45, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj46);
        org.junit.Assert.assertEquals("'" + str47 + "' != '" + "UTF-8" + "'", str47, "UTF-8");
        org.junit.Assert.assertEquals("'" + str48 + "' != '" + "UTF-8" + "'", str48, "UTF-8");
        org.junit.Assert.assertEquals("'" + str50 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str50, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertNotNull(charset52);
        org.junit.Assert.assertEquals("'" + str53 + "' != '" + "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001" + "'", str53, "=000=000=000=000=001=000=001=000=000=000=000=000=001=001=000=001=000=001=00=\r\n1=000=001=000=000=000=000=001=000=000=000=000=000=001=000=001=000=001=000=\r\n=000=000=001=000=001=001=000=000=000=000=001=000=001=000=000=000=000=000=00=\r\n1=000=001=001=000=000=001=001=001=000=001=000=000=000=001=001=001=000=001=\r\n=000=000=000=000=000=001");
        org.junit.Assert.assertEquals("'" + str54 + "' != '" + "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd" + "'", str54, "\u2461\u7072\u3124\u3979\u746e\u3936\u4666\u2476\u4578\u4541\u7364\u4330\u3252\u6336\u6c42\u4643\u3270\u4878\ufffd");
        org.junit.Assert.assertEquals("'" + str55 + "' != '" + "=?UTF-16BE?Q?=00$=006=00$=00o=00l=00h=00A=00U=00V=00h=000=00$=00f=00d=002=00x=00F=00X=00N=00N=00K=00W=00O=00X=003=00f=00O=00Q=00Q=00k=00K=00u=001=00d=00E=00D=00I=007=00A=00b=00q=00o=00o=00F=00E=00N=00R=008=00N=00K=00m=00z=00v=00t=00.=00X=00I=00d=00W=00U=00U=00e=00d=00S=00G=007=00/=00q=00x=00n=003=00D=00c=00l=00g=004=00n=00o=00x=000=00C=00e=00F=00S=00D=00y=00F=00w=009=00A=00e=00y=009=00W=00M=00N=003=000?=" + "'", str55, "=?UTF-16BE?Q?=00$=006=00$=00o=00l=00h=00A=00U=00V=00h=000=00$=00f=00d=002=00x=00F=00X=00N=00N=00K=00W=00O=00X=003=00f=00O=00Q=00Q=00k=00K=00u=001=00d=00E=00D=00I=007=00A=00b=00q=00o=00o=00F=00E=00N=00R=008=00N=00K=00m=00z=00v=00t=00.=00X=00I=00d=00W=00U=00U=00e=00d=00S=00G=007=00/=00q=00x=00n=003=00D=00c=00l=00g=004=00n=00o=00x=000=00C=00e=00F=00S=00D=00y=00F=00w=009=00A=00e=00y=009=00W=00M=00N=003=000?=");
        org.junit.Assert.assertEquals("'" + obj56 + "' != '" + "OLAVFD" + "'", obj56, "OLAVFD");
    }

    @Test
    public void test2144() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2144");
        org.apache.commons.codec.language.Nysiis nysiis1 = new org.apache.commons.codec.language.Nysiis(true);
        java.lang.String str3 = nysiis1.encode("e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        java.lang.String str5 = nysiis1.nysiis("");
        boolean boolean6 = nysiis1.isStrict();
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "EFDBAC" + "'", str3, "EFDBAC");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "" + "'", str5, "");
        org.junit.Assert.assertTrue("'" + boolean6 + "' != '" + true + "'", boolean6 == true);
    }

    @Test
    public void test2145() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2145");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[60, -65, 19, 53, 96, 56, -81, 78, 46, 63, 19, 50, 106, -34, -32, -82, -66, 85, 56, 64]");
    }

    @Test
    public void test2146() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2146");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic0 = new org.apache.commons.codec.language.ColognePhonetic();
        boolean boolean3 = colognePhonetic0.isEncodeEqual("f59b7efafd800e27b47a488d30615c73", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic4 = new org.apache.commons.codec.language.ColognePhonetic();
        java.lang.String str6 = colognePhonetic4.encode("a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
        java.lang.String str8 = colognePhonetic4.encode("b2Aup9HxaW1JY");
        java.lang.String str10 = colognePhonetic4.encode("c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a");
        java.lang.String str12 = colognePhonetic4.colognePhonetic("org.apache.commons.codec.EncoderException: 49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6");
        java.lang.Object obj13 = colognePhonetic0.encode((java.lang.Object) str12);
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "041312381228231821282818232313" + "'", str6, "041312381228231821282818232313");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "11483" + "'", str8, "11483");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "828213832432323283231" + "'", str10, "828213832432323283231");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "074144668286427481268138212338282381323183123" + "'", str12, "074144668286427481268138212338282381323183123");
        org.junit.Assert.assertEquals("'" + obj13 + "' != '" + "" + "'", obj13, "");
    }

    @Test
    public void test2147() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2147");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("AWrLOQlxe3HJg");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$pMvsk7hw$AUNAxFm5TFdNn9zh5M.g7pMuxlgu1qUuTCVtWJwZ9CySg9O774iAWXppVDVp6aZJf4bQYzZ8dc2W9bkbO3fYw." + "'", str1, "$6$pMvsk7hw$AUNAxFm5TFdNn9zh5M.g7pMuxlgu1qUuTCVtWJwZ9CySg9O774iAWXppVDVp6aZJf4bQYzZ8dc2W9bkbO3fYw.");
    }

    @Test
    public void test2148() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2148");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex("8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "3d72dbaec5c47f3160507e33b7ea6996a7d00ff750d0bdc256842bc01dbc5612247cb5f459ad99bcdd548cd9d0eb8bb7" + "'", str1, "3d72dbaec5c47f3160507e33b7ea6996a7d00ff750d0bdc256842bc01dbc5612247cb5f459ad99bcdd548cd9d0eb8bb7");
    }

    @Test
    public void test2149() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest4.test2149");
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator0 = org.apache.commons.codec.language.bm.Rule.Phoneme.COMPARATOR;
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator1 = phonemeComparator0.reversed();
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator2 = org.apache.commons.codec.language.bm.Rule.Phoneme.COMPARATOR;
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator3 = phonemeComparator2.reversed();
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator4 = phonemeComparator0.thenComparing(phonemeComparator2);
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator5 = phonemeComparator0.reversed();
        java.util.Comparator<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeComparator6 = phonemeComparator0.reversed();
        org.junit.Assert.assertNotNull(phonemeComparator0);
        org.junit.Assert.assertNotNull(phonemeComparator1);
        org.junit.Assert.assertNotNull(phonemeComparator2);
        org.junit.Assert.assertNotNull(phonemeComparator3);
        org.junit.Assert.assertNotNull(phonemeComparator4);
        org.junit.Assert.assertNotNull(phonemeComparator5);
        org.junit.Assert.assertNotNull(phonemeComparator6);
    }
}
