import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RegressionTest0 {

    public static boolean debug = false;

    @Test
    public void test0001() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0001");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex("99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff" + "'", str1, "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
    }

    @Test
    public void test0002() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0002");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5, "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
    }

    @Test
    public void test0003() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0003");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex("", "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0004() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0004");
        byte[] byteArray2 = new byte[] { (byte) 10, (byte) 0 };
        // The following exception was thrown during execution in test generation
        try {
            long[] longArray6 = org.apache.commons.codec.digest.MurmurHash3.hash128x64(byteArray2, 100, (int) (short) 1, 1);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 100 out of bounds for length 2");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[10, 0]");
    }

    @Test
    public void test0005() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0005");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("hi!", "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm hi! not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0006() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0006");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64((short) 1);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + (-3032679231428807052L) + "'", long1 == (-3032679231428807052L));
    }

    @Test
    public void test0007() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0007");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.Blake3 blake3_7 = org.apache.commons.codec.digest.Blake3.initKeyedHash(byteArray5);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
    }

    @Test
    public void test0008() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0008");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex("AAAAAAA");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea" + "'", str1, "0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
    }

    @Test
    public void test0009() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0009");
        int int1 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) (byte) 10);
        org.junit.Assert.assertTrue("'" + int1 + "' != '" + 1757052779 + "'", int1 == 1757052779);
    }

    @Test
    public void test0010() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0010");
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        org.apache.commons.codec.CodecPolicy codecPolicy4 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_5 = new org.apache.commons.codec.binary.Base64(0, byteArray2, true, codecPolicy4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: codecPolicy");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
    }

    @Test
    public void test0011() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0011");
        char[] charArray4 = new char[] { 'a', '#', '#', ' ' };
        byte[] byteArray7 = new byte[] { (byte) 1, (byte) 100 };
        // The following exception was thrown during execution in test generation
        try {
            int int9 = org.apache.commons.codec.binary.Hex.decodeHex(charArray4, byteArray7, (int) (short) 0);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Illegal hexadecimal character # at index 1");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray4);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray4), "a## ");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray4), "a## ");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray4), "[a, #, #,  ]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[1, 100]");
    }

    @Test
    public void test0012() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0012");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.util.Random random7 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5, random7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
    }

    @Test
    public void test0013() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0013");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("99448658175a0534e08dbca1fe67b58231a53eec");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1" + "'", str1, "$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
    }

    @Test
    public void test0014() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0014");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0015() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0015");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32 base32_2 = new org.apache.commons.codec.binary.Base32(false, (byte) 100);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: pad must not be in alphabet or whitespace");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0016() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0016");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0017() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0017");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        byte[] byteArray4 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray2, byteArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
    }

    @Test
    public void test0018() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0018");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex("", "99448658175a0534e08dbca1fe67b58231a53eec");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0019() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0019");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.CodecPolicy codecPolicy3 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base16OutputStream base16OutputStream4 = new org.apache.commons.codec.binary.Base16OutputStream(outputStream0, false, true, codecPolicy3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: codecPolicy");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
    }

    @Test
    public void test0020() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0020");
        org.apache.commons.codec.binary.Hex hex0 = new org.apache.commons.codec.binary.Hex();
        java.nio.ByteBuffer byteBuffer1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = hex0.decode(byteBuffer1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0021() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0021");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray3, "0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
    }

    @Test
    public void test0022() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0022");
        // The following exception was thrown during execution in test generation
        try {
            long long3 = org.apache.commons.codec.digest.MurmurHash2.hash64("hi!", (int) (short) 100, (int) (byte) 10);
            org.junit.Assert.fail("Expected exception of type java.lang.StringIndexOutOfBoundsException; message: begin 100, end 110, length 3");
        } catch (java.lang.StringIndexOutOfBoundsException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0023() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0023");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_224;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-224" + "'", str0, "SHA-224");
    }

    @Test
    public void test0024() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0024");
        java.lang.String str0 = org.apache.commons.codec.CharEncoding.UTF_8;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "UTF-8" + "'", str0, "UTF-8");
    }

    @Test
    public void test0025() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0025");
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesUnchecked("AAAAAAA", "");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalStateException; message: : java.io.UnsupportedEncodingException: ");
        } catch (java.lang.IllegalStateException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0026() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0026");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha256("hi!");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray1, "AAAAAAA");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: AAAAAAA");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-64, -35, -42, 44, 119, 23, 24, 14, 127, -5, -118, 21, -69, -106, 116, -45, -20, -110, 89, 46, 11, 122, -57, -47, -43, 40, -104, 54, -76, 85, 59, -30]");
    }

    @Test
    public void test0027() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0027");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA3_256;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA3-256" + "'", str0, "SHA3-256");
    }

    @Test
    public void test0028() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0028");
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme0 = null;
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme1 = null;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet2 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Rule.Phoneme phoneme3 = new org.apache.commons.codec.language.bm.Rule.Phoneme(phoneme0, phoneme1, languageSet2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0029() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0029");
        // The following exception was thrown during execution in test generation
        try {
            java.io.InputStream inputStream1 = org.apache.commons.codec.Resources.getInputStream("SHA3-256");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Unable to resolve required resource: SHA3-256");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0030() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0030");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("UTF-8");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0031() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0031");
        java.nio.ByteBuffer byteBuffer0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.binary.Hex.encodeHexString(byteBuffer0, false);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0032() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0032");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = phoneticEngine4.encode("99448658175a0534e08dbca1fe67b58231a53eec", languageSet6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0033() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0033");
        char char0 = org.apache.commons.codec.language.Soundex.SILENT_MARKER;
        org.junit.Assert.assertTrue("'" + char0 + "' != '" + '-' + "'", char0 == '-');
    }

    @Test
    public void test0034() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0034");
        java.lang.String str0 = org.apache.commons.codec.CharEncoding.UTF_16LE;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "UTF-16LE" + "'", str0, "UTF-16LE");
    }

    @Test
    public void test0035() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0035");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteBuffer1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "MD2 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0036() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0036");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.nio.ByteBuffer byteBuffer1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteBuffer1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0037() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0037");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0038() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0038");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA3_512;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA3-512" + "'", str0, "SHA3-512");
    }

    @Test
    public void test0039() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0039");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) '4', 0L);
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + (-1877720325) + "'", int2 == (-1877720325));
    }

    @Test
    public void test0040() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0040");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512Hex("");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" + "'", str1, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    @Test
    public void test0041() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0041");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = new byte[] { (byte) 100 };
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray3);
        java.io.InputStream inputStream6 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray5, inputStream6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[100]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[48, 49, 49, 48, 48, 49, 48, 48]");
    }

    @Test
    public void test0042() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0042");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0043() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0043");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        java.io.InputStream inputStream14 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str15 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray5, inputStream14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
    }

    @Test
    public void test0044() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0044");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex("", "0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0045() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0045");
        java.lang.String str0 = org.apache.commons.codec.language.RefinedSoundex.US_ENGLISH_MAPPING_STRING;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "01360240043788015936020505" + "'", str0, "01360240043788015936020505");
    }

    @Test
    public void test0046() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0046");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md2Hex("ffffff");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "2ef0725975afd171e9cb76444b4969c3" + "'", str1, "2ef0725975afd171e9cb76444b4969c3");
    }

    @Test
    public void test0047() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0047");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha512((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0048() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0048");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha1Hex("UTF-8");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "663b90c899fa25a111067be0c22ffc64dcf581c2" + "'", str1, "663b90c899fa25a111067be0c22ffc64dcf581c2");
    }

    @Test
    public void test0049() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0049");
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(true, codecPolicy1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: codecPolicy");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0050() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0050");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        base64OutputStream1.write(byteArray5);
        java.util.BitSet bitSet9 = null;
        byte[] byteArray11 = new byte[] { (byte) 100 };
        byte[] byteArray12 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet9, byteArray11);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray12);
        byte[] byteArray14 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray12);
        // The following exception was thrown during execution in test generation
        try {
            base64OutputStream1.write(byteArray12, (-690116322), (int) (short) 10);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: null");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[100]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[100]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[48, 49, 49, 48, 48, 49, 48, 48]");
    }

    @Test
    public void test0051() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0051");
        java.lang.Throwable throwable0 = null;
        org.apache.commons.codec.DecoderException decoderException1 = new org.apache.commons.codec.DecoderException(throwable0);
        java.lang.Throwable throwable2 = null;
        org.apache.commons.codec.DecoderException decoderException3 = new org.apache.commons.codec.DecoderException(throwable2);
        // The following exception was thrown during execution in test generation
        try {
            decoderException1.addSuppressed(throwable2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot suppress a null exception.");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0052() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0052");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = new byte[] { (byte) 100 };
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str6 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray4, "");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: ");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[100]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
    }

    @Test
    public void test0053() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0053");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray6 = quotedPrintableCodec1.encode(byteArray5);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -3 out of bounds for length 0");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
    }

    @Test
    public void test0054() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0054");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256Hex("", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0055() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0055");
        java.lang.String str0 = org.apache.commons.codec.language.Soundex.US_ENGLISH_MAPPING_STRING;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "01230120022455012623010202" + "'", str0, "01230120022455012623010202");
    }

    @Test
    public void test0056() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0056");
        // The following exception was thrown during execution in test generation
        try {
            java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset("");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: ");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0057() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0057");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = uRLCodec1.encode("663b90c899fa25a111067be0c22ffc64dcf581c2");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: hi!");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0058() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0058");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0059() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0059");
        java.io.InputStream inputStream0 = java.io.InputStream.nullInputStream();
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray8, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str12 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray8);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray8);
        org.apache.commons.codec.CodecPolicy codecPolicy14 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64InputStream base64InputStream15 = new org.apache.commons.codec.binary.Base64InputStream(inputStream0, false, (int) '4', byteArray8, codecPolicy14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: codecPolicy");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(inputStream0);
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str11, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "AAAAAAA" + "'", str12, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str13, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
    }

    @Test
    public void test0060() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0060");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex5 = new org.apache.commons.codec.language.RefinedSoundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = refinedSoundex5.encode("0Acd8L3u4hVxI");
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 3 out of bounds for length 3");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0061() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0061");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd");
// flaky:         org.junit.Assert.assertEquals("'" + str2 + "' != '" + "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397" + "'", str2, "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
    }

    @Test
    public void test0062() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0062");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray2, "$1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: $1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
    }

    @Test
    public void test0063() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0063");
        java.lang.String str0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET_NAME;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "UTF-8" + "'", str0, "UTF-8");
    }

    @Test
    public void test0064() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0064");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = new byte[] { (byte) 100 };
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray3);
        long long7 = org.apache.commons.codec.digest.MurmurHash2.hash64(byteArray5, (int) (byte) 0);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[100]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertTrue("'" + long7 + "' != '" + (-7207201254813729732L) + "'", long7 == (-7207201254813729732L));
    }

    @Test
    public void test0065() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0065");
        byte[] byteArray3 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("SHA3-256", "ABUAA2IAEE======");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_6 = new org.apache.commons.codec.binary.Base64(10, byteArray3, false, codecPolicy5);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [`m8???y????GJP?owq'?l???y?A?_?d`]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[96, 109, 56, 8, -108, -2, 121, -63, -27, -38, 30, 71, 74, 80, -13, 111, 119, 113, 39, -26, 108, 15, -1, -110, 121, -99, 65, 6, 95, -11, 100, 96]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0066() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0066");
        byte[] byteArray3 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray3, true);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.PercentCodec percentCodec7 = new org.apache.commons.codec.net.PercentCodec(byteArray3, false);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: bitIndex < 0: -1");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "ffffff" + "'", str5, "ffffff");
    }

    @Test
    public void test0067() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0067");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils("");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException:  MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0068() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0068");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64((-1877720325));
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + (-1930345184306861225L) + "'", long1 == (-1930345184306861225L));
    }

    @Test
    public void test0069() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0069");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.QCodec qCodec1 = new org.apache.commons.codec.net.QCodec("ffffff");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: ffffff");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0070() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0070");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex("0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107" + "'", str1, "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
    }

    @Test
    public void test0071() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0071");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0072() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0072");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex5 = new org.apache.commons.codec.language.RefinedSoundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = refinedSoundex5.encode("UTF-16LE");
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 20 out of bounds for length 3");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0073() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0073");
        java.nio.charset.Charset charset0 = null;
        java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset(charset0);
        org.apache.commons.codec.binary.Hex hex2 = new org.apache.commons.codec.binary.Hex(charset1);
        java.nio.ByteBuffer byteBuffer3 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = hex2.decode(byteBuffer3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset1);
    }

    @Test
    public void test0074() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0074");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) 100, (long) 0);
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + 629192958 + "'", int2 == 629192958);
    }

    @Test
    public void test0075() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0075");
        int int1 = org.apache.commons.codec.digest.MurmurHash3.hash32("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertTrue("'" + int1 + "' != '" + (-1612190696) + "'", int1 == (-1612190696));
    }

    @Test
    public void test0076() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0076");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray1, "UTF-8");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: UTF-8");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
    }

    @Test
    public void test0077() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0077");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.MD2;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "MD2" + "'", str0, "MD2");
    }

    @Test
    public void test0078() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0078");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("d41d8cd98f00b204e9800998ecf8427e", "$apr1$9ytn96Ff$vExEAsdC02Rc6lBFC2pHx/");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm d41d8cd98f00b204e9800998ecf8427e not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0079() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0079");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = new byte[] { (byte) 100 };
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            int int8 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray4, 1, (int) (byte) 100, 100);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 64 out of bounds for length 64");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[100]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
    }

    @Test
    public void test0080() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0080");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj6 = soundex4.encode((java.lang.Object) "2ef0725975afd171e9cb76444b4969c3");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: The character is not mapped: E (index=4)");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0081() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0081");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        byte[] byteArray8 = uRLCodec1.decode(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str10 = uRLCodec1.encode("d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: hi!");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str7, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
    }

    @Test
    public void test0082() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0082");
        java.lang.String[] strArray0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.values();
        org.junit.Assert.assertNotNull(strArray0);
    }

    @Test
    public void test0083() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0083");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        java.io.RandomAccessFile randomAccessFile3 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, randomAccessFile3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0084() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0084");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.md2((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0085() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0085");
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getDigest("");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException:  MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0086() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0086");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            int int7 = soundex4.difference("$1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/", "");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: The character is not mapped: W (index=22)");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0087() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0087");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64((byte) 100);
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + true + "'", boolean1 == true);
    }

    @Test
    public void test0088() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0088");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        // The following exception was thrown during execution in test generation
        try {
            int int5 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray2, (-1877720325), (int) '-');
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -1877720326 out of bounds for length 10");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
    }

    @Test
    public void test0089() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0089");
        long long0 = org.apache.commons.codec.digest.MurmurHash3.NULL_HASHCODE;
        org.junit.Assert.assertTrue("'" + long0 + "' != '" + 2862933555777941757L + "'", long0 == 2862933555777941757L);
    }

    @Test
    public void test0090() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0090");
        org.apache.commons.codec.CharEncoding charEncoding0 = new org.apache.commons.codec.CharEncoding();
    }

    @Test
    public void test0091() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0091");
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme0 = null;
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme1 = null;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet2 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Rule.Phoneme phoneme3 = new org.apache.commons.codec.language.bm.Rule.Phoneme(phoneme0, phoneme1, languageSet2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(languageSet2);
    }

    @Test
    public void test0092() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0092");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        byte[] byteArray8 = uRLCodec1.decode(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str11 = uRLCodec1.decode("6IiiRyxmjcARw", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: 84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str7, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
    }

    @Test
    public void test0093() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0093");
        java.lang.String str0 = org.apache.commons.codec.language.bm.Rule.ALL;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "ALL" + "'", str0, "ALL");
    }

    @Test
    public void test0094() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0094");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        org.apache.commons.codec.net.PercentCodec percentCodec15 = new org.apache.commons.codec.net.PercentCodec(byteArray5, true);
        // The following exception was thrown during execution in test generation
        try {
            long long17 = org.apache.commons.codec.digest.MurmurHash2.hash64(byteArray5, 10);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 5 out of bounds for length 5");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
    }

    @Test
    public void test0095() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0095");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        java.nio.file.Path path3 = null;
        java.nio.file.OpenOption[] openOptionArray4 = new java.nio.file.OpenOption[] {};
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest5 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, path3, openOptionArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(openOptionArray4);
    }

    @Test
    public void test0096() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0096");
        int int0 = org.apache.commons.codec.digest.MurmurHash3.DEFAULT_SEED;
        org.junit.Assert.assertTrue("'" + int0 + "' != '" + 104729 + "'", int0 == 104729);
    }

    @Test
    public void test0097() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0097");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex("\u4668\u8976\u82cc\ud2b1\uee0c\uae8d\uc559\u4729\u1f81\u9cc5\u9ee1\u26f5\ubd24\u3b18\u5257\u7414\u413a\ueed5\u780b\u5fb1\u1090\u0387\u15be\ued1b\u4a15\ub31c\u8d96\u74fb\ufffd\u191c", "0Ac7cg1i0oNqE");
// flaky:         org.junit.Assert.assertEquals("'" + str2 + "' != '" + "202501fe2df741220d38e4ee0487ef0aae4dbf81ea9af5e7ccb75d0eba0c5591b27fd090e0ef62e26c5813d21bf9ce1f1bb3b28da49a1b4996abb8defa283943" + "'", str2, "202501fe2df741220d38e4ee0487ef0aae4dbf81ea9af5e7ccb75d0eba0c5591b27fd090e0ef62e26c5813d21bf9ce1f1bb3b28da49a1b4996abb8defa283943");
    }

    @Test
    public void test0098() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0098");
        int int0 = org.apache.commons.codec.binary.BaseNCodec.PEM_CHUNK_SIZE;
        org.junit.Assert.assertTrue("'" + int0 + "' != '" + 64 + "'", int0 == 64);
    }

    @Test
    public void test0099() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0099");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_512_256;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-512/256" + "'", str0, "SHA-512/256");
    }

    @Test
    public void test0100() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0100");
        org.apache.commons.codec.language.Soundex soundex0 = org.apache.commons.codec.language.Soundex.US_ENGLISH_GENEALOGY;
        org.junit.Assert.assertNotNull(soundex0);
    }

    @Test
    public void test0101() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0101");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0102() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0102");
        java.lang.Throwable throwable0 = null;
        org.apache.commons.codec.DecoderException decoderException1 = new org.apache.commons.codec.DecoderException(throwable0);
        org.apache.commons.codec.EncoderException encoderException2 = new org.apache.commons.codec.EncoderException();
        decoderException1.addSuppressed((java.lang.Throwable) encoderException2);
        java.lang.String str4 = decoderException1.toString();
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "org.apache.commons.codec.DecoderException" + "'", str4, "org.apache.commons.codec.DecoderException");
    }

    @Test
    public void test0103() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0103");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = quotedPrintableCodec1.encode("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1", "SHA-224");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: SHA-224");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0104() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0104");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0105() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0105");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0Acd8L3u4hVxI");
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray15 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray5, false, true, (-1));
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Input array too big, the output array would be bigger (8) than the specified maximum size of -1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0Ac7cg1i0oNqE" + "'", str11, "0Ac7cg1i0oNqE");
    }

    @Test
    public void test0106() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0106");
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex0 = org.apache.commons.codec.language.RefinedSoundex.US_ENGLISH;
        int int3 = refinedSoundex0.difference("$1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.", "01360240043788015936020505");
        org.junit.Assert.assertNotNull(refinedSoundex0);
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + 0 + "'", int3 == 0);
    }

    @Test
    public void test0107() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0107");
        java.lang.Throwable throwable0 = null;
        org.apache.commons.codec.DecoderException decoderException1 = new org.apache.commons.codec.DecoderException(throwable0);
        org.apache.commons.codec.EncoderException encoderException2 = new org.apache.commons.codec.EncoderException();
        decoderException1.addSuppressed((java.lang.Throwable) encoderException2);
        java.lang.Throwable throwable4 = null;
        org.apache.commons.codec.DecoderException decoderException5 = new org.apache.commons.codec.DecoderException(throwable4);
        org.apache.commons.codec.EncoderException encoderException6 = new org.apache.commons.codec.EncoderException();
        decoderException5.addSuppressed((java.lang.Throwable) encoderException6);
        encoderException2.addSuppressed((java.lang.Throwable) encoderException6);
        java.lang.Throwable[] throwableArray9 = encoderException2.getSuppressed();
        java.lang.String str10 = encoderException2.toString();
        org.junit.Assert.assertNotNull(throwableArray9);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "org.apache.commons.codec.EncoderException" + "'", str10, "org.apache.commons.codec.EncoderException");
    }

    @Test
    public void test0108() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0108");
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getDigest("1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: 1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397 MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0109() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0109");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        java.lang.String str4 = soundex2.soundex("6IiiRyxmjcARw");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "I6ae" + "'", str4, "I6ae");
    }

    @Test
    public void test0110() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0110");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        byte[] byteArray11 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray11);
        java.lang.String str14 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray11, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str15 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray11);
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray11);
        // The following exception was thrown during execution in test generation
        try {
            int int19 = inputStream3.readNBytes(byteArray11, 1757052779, 1757052779);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: Range [1757052779, 1757052779 + 1757052779) out of bounds for length 5");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str12, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str14, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "AAAAAAA" + "'", str15, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str16, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
    }

    @Test
    public void test0111() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0111");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = phoneticEngine4.encode("MD2");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(ruleType5);
    }

    @Test
    public void test0112() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0112");
        java.lang.Throwable throwable0 = null;
        org.apache.commons.codec.DecoderException decoderException1 = new org.apache.commons.codec.DecoderException(throwable0);
        org.apache.commons.codec.EncoderException encoderException2 = new org.apache.commons.codec.EncoderException();
        decoderException1.addSuppressed((java.lang.Throwable) encoderException2);
        java.lang.Throwable throwable4 = null;
        org.apache.commons.codec.DecoderException decoderException5 = new org.apache.commons.codec.DecoderException(throwable4);
        org.apache.commons.codec.EncoderException encoderException6 = new org.apache.commons.codec.EncoderException();
        decoderException5.addSuppressed((java.lang.Throwable) encoderException6);
        encoderException2.addSuppressed((java.lang.Throwable) encoderException6);
        java.lang.Throwable throwable9 = null;
        org.apache.commons.codec.DecoderException decoderException10 = new org.apache.commons.codec.DecoderException(throwable9);
        // The following exception was thrown during execution in test generation
        try {
            encoderException2.addSuppressed(throwable9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot suppress a null exception.");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0113() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0113");
        org.apache.commons.codec.EncoderException encoderException1 = new org.apache.commons.codec.EncoderException("2ef0725975afd171e9cb76444b4969c3");
    }

    @Test
    public void test0114() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0114");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            int int6 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray2, 1757052779, (int) '4');
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 28 out of bounds for length 28");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[61, 68, 68, 61, 48, 69, 76, 94, 61, 65, 70, 61, 65, 55, 61, 70, 49, 61, 49, 50, 61, 49, 65, 61, 49, 57, 61, 48, 53, 61, 56, 51, 61, 56, 54, 61, 48, 56, 61, 49, 52, 61, 65, 50, 121, 61, 65, 53, 126, 110, 61, 69, 53, 61, 68, 48, 61, 69, 51, 38, 61, 66, 57, 85, 39, 61, 66, 50]");
    }

    @Test
    public void test0115() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0115");
        boolean boolean1 = org.apache.commons.codec.digest.HmacUtils.isAvailable("$1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0116() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0116");
        java.io.InputStream inputStream0 = null;
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream6 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, true, (int) (byte) 0, byteArray4, codecPolicy5);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha512(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0117() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0117");
        org.apache.commons.codec.Charsets charsets0 = new org.apache.commons.codec.Charsets();
    }

    @Test
    public void test0118() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0118");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str11 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray9, "$1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: $1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
    }

    @Test
    public void test0119() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0119");
        java.io.InputStream inputStream0 = null;
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream6 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, true, (int) (byte) 0, byteArray4, codecPolicy5);
        base32InputStream6.mark((int) '-');
        org.apache.commons.codec.net.URLCodec uRLCodec12 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet13 = null;
        byte[] byteArray15 = new byte[] { (byte) 100 };
        byte[] byteArray16 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet13, byteArray15);
        byte[] byteArray17 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray16);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray16);
        byte[] byteArray19 = uRLCodec12.decode(byteArray16);
        byte[] byteArray20 = null;
        byte[] byteArray21 = uRLCodec12.decode(byteArray20);
        byte[] byteArray27 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str28 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray27);
        java.lang.String str30 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray27, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_31 = new org.apache.commons.codec.binary.Base16();
        boolean boolean33 = base16_31.isInAlphabet("AAAAAAA");
        byte[] byteArray37 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str39 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray37, true);
        java.lang.String str40 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray37);
        boolean boolean42 = base16_31.isInAlphabet(byteArray37, true);
        byte[] byteArray43 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray27, byteArray37);
        byte[] byteArray44 = uRLCodec12.encode(byteArray43);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64InputStream base64InputStream45 = new org.apache.commons.codec.binary.Base64InputStream((java.io.InputStream) base32InputStream6, true, (-690116322), byteArray44);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [%1DtU%60%9D%EB%23%99%E3%A9%E8%9D%F6%86%EF+%8Bi-E%BE%17%D2%E2%8C%21%DAn%88%E8%8D.]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[100]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[100]");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str18, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[100]");
        org.junit.Assert.assertNull(byteArray21);
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str28 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str28, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str30, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean33 + "' != '" + true + "'", boolean33 == true);
        org.junit.Assert.assertNotNull(byteArray37);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray37), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str39 + "' != '" + "ffffff" + "'", str39, "ffffff");
        org.junit.Assert.assertEquals("'" + str40 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str40, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean42 + "' != '" + false + "'", boolean42 == false);
        org.junit.Assert.assertNotNull(byteArray43);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray43), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray44);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray44), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
    }

    @Test
    public void test0120() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0120");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0121() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0121");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        int int6 = phoneticEngine4.getMaxPhonemes();
        org.junit.Assert.assertNull(ruleType5);
        org.junit.Assert.assertTrue("'" + int6 + "' != '" + (-1) + "'", int6 == (-1));
    }

    @Test
    public void test0122() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0122");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_512Digest();
        java.io.InputStream inputStream1 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream4 = new org.apache.commons.codec.binary.Base16InputStream(inputStream1, true, true);
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest5 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-512 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0123() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0123");
        org.apache.commons.codec.binary.Base32 base32_2 = new org.apache.commons.codec.binary.Base32(true, (byte) 0);
    }

    @Test
    public void test0124() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0124");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.nio.file.Path path1 = null;
        java.nio.file.OpenOption openOption2 = null;
        java.nio.file.OpenOption[] openOptionArray3 = new java.nio.file.OpenOption[] { openOption2 };
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, path1, openOptionArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(openOptionArray3);
    }

    @Test
    public void test0125() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0125");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            long[] longArray1 = org.apache.commons.codec.digest.MurmurHash3.hash128x64(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0126() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0126");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.getDigest("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", messageDigest1);
        java.nio.file.Path path3 = null;
        java.nio.file.OpenOption[] openOptionArray4 = new java.nio.file.OpenOption[] {};
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest1, path3, openOptionArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(openOptionArray4);
    }

    @Test
    public void test0127() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0127");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.NameType nameType1 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType2 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet3 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap4 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType1, ruleType2, languageSet3);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine6 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType2, true);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: ruleType must not be RULES");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + nameType1 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType1.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType2 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType2.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet3);
        org.junit.Assert.assertNotNull(strMap4);
    }

    @Test
    public void test0128() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0128");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getMd5Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "MD5 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0129() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0129");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = phoneticEngine4.encode("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", languageSet6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0130() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0130");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray1 = null;
        byte[] byteArray2 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray1);
        org.junit.Assert.assertNull(byteArray2);
    }

    @Test
    public void test0131() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0131");
        java.lang.String str0 = org.apache.commons.codec.CharEncoding.UTF_16BE;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "UTF-16BE" + "'", str0, "UTF-16BE");
    }

    @Test
    public void test0132() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0132");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        java.lang.Class<?> wildcardClass1 = messageDigest0.getClass();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(wildcardClass1);
    }

    @Test
    public void test0133() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0133");
        org.apache.commons.codec.digest.DigestUtils digestUtils0 = new org.apache.commons.codec.digest.DigestUtils();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = digestUtils0.digestAsHex(file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0134() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0134");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256Hex("", "99448658175a0534e08dbca1fe67b58231a53eec");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0135() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0135");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0136() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0136");
        byte[] byteArray0 = null;
        byte[] byteArray1 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray0);
        org.junit.Assert.assertNull(byteArray1);
    }

    @Test
    public void test0137() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0137");
        org.apache.commons.codec.binary.CharSequenceUtils charSequenceUtils0 = new org.apache.commons.codec.binary.CharSequenceUtils();
    }

    @Test
    public void test0138() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0138");
        org.apache.commons.codec.digest.DigestUtils digestUtils0 = new org.apache.commons.codec.digest.DigestUtils();
        java.nio.file.Path path1 = null;
        java.nio.file.OpenOption openOption2 = null;
        java.nio.file.OpenOption[] openOptionArray3 = new java.nio.file.OpenOption[] { openOption2 };
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = digestUtils0.digestAsHex(path1, openOptionArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(openOptionArray3);
    }

    @Test
    public void test0139() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0139");
        java.io.InputStream inputStream0 = null;
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream6 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, true, (int) (byte) 0, byteArray4, codecPolicy5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base32InputStream6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0140() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0140");
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha384("", "0A01640101");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0141() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0141");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        base64OutputStream1.write(byteArray5);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream11 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base64OutputStream1, true, false);
        base16OutputStream11.flush();
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
    }

    @Test
    public void test0142() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0142");
        boolean boolean1 = org.apache.commons.codec.digest.HmacUtils.isAvailable("org.apache.commons.codec.EncoderException");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0143() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0143");
        boolean boolean1 = org.apache.commons.codec.digest.HmacUtils.isAvailable("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0144() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0144");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = bCodec2.encode("84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "$1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: $1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
    }

    @Test
    public void test0145() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0145");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_224("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_4 = new org.apache.commons.codec.binary.Base64(10, byteArray2, false);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [?B??*???3?a???m??6?O??6?\"<[]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-7, 66, -110, 8, 42, -107, -82, -73, 51, -90, 97, -114, -116, -15, 109, -48, -41, -117, 54, 3, 79, 6, -51, 54, -56, 34, 60, 91]");
    }

    @Test
    public void test0146() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0146");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult2 = doubleMetaphone0.new DoubleMetaphoneResult((-1612190696));
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: reflection call to org.apache.commons.codec.language.DoubleMetaphone$DoubleMetaphoneResult with null for superclass argument");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0147() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0147");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_1;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-1" + "'", str0, "SHA-1");
    }

    @Test
    public void test0148() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0148");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        org.apache.commons.codec.digest.HmacUtils hmacUtils8 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec10 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        java.lang.String str19 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray16, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str20 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray16);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray16);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray16);
        java.lang.Object obj23 = quotedPrintableCodec10.decode((java.lang.Object) byteArray16);
        org.apache.commons.codec.digest.HmacUtils hmacUtils24 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, byteArray16);
        java.lang.String str26 = hmacUtils24.hmacHex("6IiiRyxmjcARw");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str19, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "AAAAAAA" + "'", str20, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str21, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str22, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj23);
        org.junit.Assert.assertEquals("'" + str26 + "' != '" + "50d099290876d18e40b67f38cde88ecd91b8d6b69c349dc179b209e2" + "'", str26, "50d099290876d18e40b67f38cde88ecd91b8d6b69c349dc179b209e2");
    }

    @Test
    public void test0149() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0149");
        org.apache.commons.codec.digest.Crypt crypt0 = new org.apache.commons.codec.digest.Crypt();
    }

    @Test
    public void test0150() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0150");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex("84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "ALL");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf" + "'", str2, "c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf");
    }

    @Test
    public void test0151() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0151");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = uRLCodec1.encode(byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str10 = uRLCodec1.decode("$1$W/jMtuf7$UGQw9DE1K6Iok/.1r5v0T/", "AAAAAAA");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: AAAAAAA");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
    }

    @Test
    public void test0152() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0152");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream4 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream0, (org.apache.commons.codec.binary.BaseNCodec) base16_2, false);
        byte[] byteArray10 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray10);
        java.lang.String str13 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray10, "99448658175a0534e08dbca1fe67b58231a53eec");
        // The following exception was thrown during execution in test generation
        try {
            baseNCodecOutputStream4.write(byteArray10);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid octet in encoded value: 0");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str11, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str13, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
    }

    @Test
    public void test0153() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0153");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray8 = org.apache.commons.codec.digest.Blake3.keyedHash(byteArray3, byteArray6);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[61, 68, 68, 61, 48, 69, 76, 94, 61, 65, 70, 61, 65, 55, 61, 70, 49, 61, 49, 50, 61, 49, 65, 61, 49, 57, 61, 48, 53, 61, 56, 51, 61, 56, 54, 61, 48, 56, 61, 49, 52, 61, 65, 50, 121, 61, 65, 53, 126, 110, 61, 69, 53, 61, 68, 48, 61, 69, 51, 38, 61, 66, 57, 85, 39, 61, 66, 50]");
    }

    @Test
    public void test0154() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0154");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512Hex("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6" + "'", str1, "49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6");
    }

    @Test
    public void test0155() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0155");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        boolean boolean4 = base16InputStream3.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_224((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
    }

    @Test
    public void test0156() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0156");
        byte[] byteArray1 = org.apache.commons.codec.binary.Base64.decodeBase64("");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str2, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }

    @Test
    public void test0157() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0157");
        java.io.InputStream inputStream0 = null;
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream6 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, true, (int) (byte) 0, byteArray4, codecPolicy5);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.md2(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0158() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0158");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getShaDigest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-1 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0159() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0159");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        soundex4.setMaxLength((int) '#');
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0160() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0160");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        org.apache.commons.codec.language.bm.NameType nameType7 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType8 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet9 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap10 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType7, ruleType8, languageSet9);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str11 = phoneticEngine4.encode("UTF-16BE", languageSet9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(ruleType5);
        org.junit.Assert.assertTrue("'" + nameType7 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType7.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType8 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType8.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet9);
        org.junit.Assert.assertNotNull(strMap10);
    }

    @Test
    public void test0161() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0161");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("01230120022455012623010202");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: 01230120022455012623010202");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0162() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0162");
        long[] longArray1 = org.apache.commons.codec.digest.MurmurHash3.hash128("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertNotNull(longArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(longArray1), "[997987104723945410, 7475822129978770682]");
    }

    @Test
    public void test0163() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0163");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_224Digest();
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray3 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        java.io.InputStream inputStream4 = java.io.InputStream.nullInputStream();
        java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray3, inputStream4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray3);
        java.lang.String str7 = org.apache.commons.codec.binary.BinaryCodec.toAsciiString(byteArray3);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/224 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream4);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str5, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-6, -46, 89, 81, 20, -27, -60, 90, -119, 111, 52, -127, -69, 99, -25, 9, 127, -97, 16, 111, -45, 89, 28, 30, 55, -61, 15, -18]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "00001010000011010110100001000001010100010110000101000001011001110100011101000001" + "'", str7, "00001010000011010110100001000001010100010110000101000001011001110100011101000001");
    }

    @Test
    public void test0164() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0164");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Languages languages1 = org.apache.commons.codec.language.bm.Languages.getInstance("SHA-1");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Unable to resolve required resource: SHA-1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0165() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0165");
        org.apache.commons.codec.language.Soundex soundex1 = new org.apache.commons.codec.language.Soundex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        java.lang.String str3 = soundex1.encode("99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "Ae3f" + "'", str3, "Ae3f");
    }

    @Test
    public void test0166() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0166");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        java.io.InputStream inputStream10 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream13 = new org.apache.commons.codec.binary.Base16InputStream(inputStream10, true, true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str14 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray5, (java.io.InputStream) base16InputStream13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
    }

    @Test
    public void test0167() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0167");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5, "ALL");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: ALL");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
    }

    @Test
    public void test0168() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0168");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        byte[] byteArray13 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray13);
        java.lang.String str16 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray13, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str17 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray13);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray13);
        java.lang.String str20 = org.apache.commons.codec.digest.Crypt.crypt(byteArray13, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec22 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet23 = null;
        byte[] byteArray25 = new byte[] { (byte) 100 };
        byte[] byteArray26 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet23, byteArray25);
        byte[] byteArray27 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray26);
        byte[] byteArray28 = uRLCodec22.encode(byteArray27);
        java.lang.String str29 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray13, byteArray27);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj30 = bCodec2.decode((java.lang.Object) byteArray27);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type [B cannot be decoded using BCodec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str14, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str16, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "AAAAAAA" + "'", str17, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str18, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "0Acd8L3u4hVxI" + "'", str20, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[100]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[100]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str29, "d2789eba1651444e3ee6cb80db8900fa");
    }

    @Test
    public void test0169() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0169");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64("01360240043788015936020505");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + true + "'", boolean1 == true);
    }

    @Test
    public void test0170() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0170");
        org.apache.commons.codec.digest.DigestUtils digestUtils0 = new org.apache.commons.codec.digest.DigestUtils();
        java.security.MessageDigest messageDigest1 = digestUtils0.getMessageDigest();
        org.junit.Assert.assertNull(messageDigest1);
    }

    @Test
    public void test0171() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0171");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray5 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray4);
        java.io.InputStream inputStream6 = java.io.InputStream.nullInputStream();
        java.lang.String str7 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray5, inputStream6);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream8 = new org.apache.commons.codec.binary.Base64InputStream(inputStream6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj9 = bCodec2.decode((java.lang.Object) inputStream6);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type java.io.InputStream$1 cannot be decoded using BCodec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream6);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str7, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
    }

    @Test
    public void test0172() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0172");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.NameType nameType1 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang2 = org.apache.commons.codec.language.bm.Lang.instance(nameType1);
        org.apache.commons.codec.language.bm.NameType nameType3 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType4 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet5 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap6 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType3, ruleType4, languageSet5);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet7 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap8 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType1, ruleType4, languageSet7);
        // The following exception was thrown during execution in test generation
        try {
            java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap10 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType4, "");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: No rules found for gen, rules, .");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + nameType1 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType1.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang2);
        org.junit.Assert.assertTrue("'" + nameType3 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType3.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType4 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType4.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet5);
        org.junit.Assert.assertNotNull(strMap6);
        org.junit.Assert.assertNotNull(languageSet7);
        org.junit.Assert.assertNotNull(strMap8);
    }

    @Test
    public void test0173() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0173");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0174() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0174");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        byte[] byteArray3 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray2);
        java.lang.Class<?> wildcardClass4 = byteArray3.getClass();
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[61, 68, 68, 61, 48, 69, 76, 94, 61, 65, 70, 61, 65, 55, 61, 70, 49, 61, 49, 50, 61, 49, 65, 61, 49, 57, 61, 48, 53, 61, 56, 51, 61, 56, 54, 61, 48, 56, 61, 49, 52, 61, 65, 50, 121, 61, 65, 53, 126, 110, 61, 69, 53, 61, 68, 48, 61, 69, 51, 38, 61, 66, 57, 85, 39, 61, 66, 50]");
        org.junit.Assert.assertNotNull(wildcardClass4);
    }

    @Test
    public void test0175() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0175");
        java.lang.Throwable throwable1 = null;
        org.apache.commons.codec.DecoderException decoderException2 = new org.apache.commons.codec.DecoderException(throwable1);
        org.apache.commons.codec.EncoderException encoderException3 = new org.apache.commons.codec.EncoderException();
        decoderException2.addSuppressed((java.lang.Throwable) encoderException3);
        java.lang.Throwable throwable5 = null;
        org.apache.commons.codec.DecoderException decoderException6 = new org.apache.commons.codec.DecoderException(throwable5);
        org.apache.commons.codec.EncoderException encoderException7 = new org.apache.commons.codec.EncoderException();
        decoderException6.addSuppressed((java.lang.Throwable) encoderException7);
        encoderException3.addSuppressed((java.lang.Throwable) encoderException7);
        org.apache.commons.codec.DecoderException decoderException10 = new org.apache.commons.codec.DecoderException("d41d8cd98f00b204e9800998ecf8427e", (java.lang.Throwable) encoderException3);
        org.apache.commons.codec.DecoderException decoderException11 = new org.apache.commons.codec.DecoderException((java.lang.Throwable) decoderException10);
    }

    @Test
    public void test0176() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0176");
        byte[] byteArray3 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray3, true);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.Blake3 blake3_7 = org.apache.commons.codec.digest.Blake3.initKeyedHash(byteArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "ffffff" + "'", str5, "ffffff");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str6, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
    }

    @Test
    public void test0177() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0177");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64((byte) 10);
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0178() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0178");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64((short) 10);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + (-8350299967407043051L) + "'", long1 == (-8350299967407043051L));
    }

    @Test
    public void test0179() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0179");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.MD5;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "MD5" + "'", str0, "MD5");
    }

    @Test
    public void test0180() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0180");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        boolean boolean4 = base16InputStream3.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha1Hex((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
    }

    @Test
    public void test0181() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0181");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = uRLCodec1.encode(byteArray6);
        javax.crypto.Mac mac8 = org.apache.commons.codec.digest.HmacUtils.getHmacSha1(byteArray6);
        javax.crypto.Mac mac10 = org.apache.commons.codec.digest.HmacUtils.updateHmac(mac8, "00001010000011010110100001000001010100010110000101000001011001110100011101000001");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertNotNull(mac8);
        org.junit.Assert.assertNotNull(mac10);
    }

    @Test
    public void test0182() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0182");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer2 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteBuffer2);
        java.io.RandomAccessFile randomAccessFile4 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest5 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, randomAccessFile4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "MD2 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0183() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0183");
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
        java.io.File file37 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest38 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest36, file37);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
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
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0184() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0184");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex("");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    public void test0185() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0185");
        java.util.BitSet bitSet0 = null;
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
        byte[] byteArray34 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray31);
        java.util.Random random35 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str36 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray31, random35);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
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
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "ABUAA2IAEE======" + "'", str32, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[37, 48, 48, 104, 37, 48, 48, 105, 37, 48, 48, 37, 50, 49]");
    }

    @Test
    public void test0186() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0186");
        org.apache.commons.codec.digest.HmacUtils hmacUtils0 = new org.apache.commons.codec.digest.HmacUtils();
        java.util.BitSet bitSet1 = null;
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms2 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray6);
        javax.crypto.Mac mac8 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms2, byteArray7);
        byte[] byteArray14 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray14);
        java.lang.String str17 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray14, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str18 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray14);
        java.lang.String str19 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray14);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray14);
        javax.crypto.Mac mac21 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms2, byteArray14);
        org.apache.commons.codec.binary.Base32 base32_23 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet24 = null;
        byte[] byteArray26 = new byte[] { (byte) 100 };
        byte[] byteArray27 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet24, byteArray26);
        byte[] byteArray28 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray27);
        boolean boolean30 = base32_23.isInAlphabet(byteArray28, false);
        byte[] byteArray32 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str33 = base32_23.encodeAsString(byteArray32);
        org.apache.commons.codec.digest.HmacUtils hmacUtils34 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms2, byteArray32);
        byte[] byteArray35 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet1, byteArray32);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str36 = hmacUtils0.hmacHex(byteArray32);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms2 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms2.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac8);
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str15, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str17, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "AAAAAAA" + "'", str18, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str19, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str20, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac21);
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[100]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[100]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean30 + "' != '" + false + "'", boolean30 == false);
        org.junit.Assert.assertNotNull(byteArray32);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray32), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertEquals("'" + str33 + "' != '" + "ABUAA2IAEE======" + "'", str33, "ABUAA2IAEE======");
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[37, 48, 48, 104, 37, 48, 48, 105, 37, 48, 48, 37, 50, 49]");
    }

    @Test
    public void test0187() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0187");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        boolean boolean8 = base32_1.isInAlphabet(byteArray6, false);
        byte[] byteArray10 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str11 = base32_1.encodeAsString(byteArray10);
        java.math.BigInteger bigInteger12 = org.apache.commons.codec.binary.Base64.decodeInteger(byteArray10);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray10);
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
        org.junit.Assert.assertNotNull(bigInteger12);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[63, 102, 103, 26, 108, -37, -16, 20, -49, -26, -33, 101, -76, 89, 56, -83, -59, -57, -124, 1, 19, -100, -88, 15, 17, -79, -50, -75]");
    }

    @Test
    public void test0188() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0188");
        java.lang.String str2 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt("0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea", "01360240043788015936020505");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "$apr1$01360240$Sqo94M8QGdmC4Br9KQCWS/" + "'", str2, "$apr1$01360240$Sqo94M8QGdmC4Br9KQCWS/");
    }

    @Test
    public void test0189() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0189");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha1("01360240043788015936020505", "UTF-8");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[108, -112, -76, 85, 118, -81, 112, -38, -70, 108, -115, 46, -113, -53, 99, 119, 57, -110, -123, -9]");
    }

    @Test
    public void test0190() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0190");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("663b90c899fa25a111067be0c22ffc64dcf581c2");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$X8jRqUQt$f4Uob5BOcMuwkXZodo8Ty80pd9AGfD0SQU0ibBjhdzbAyytXiKp.EmPT5SJ5FZE43YRXQiuc3RDQpgAiznTFq/" + "'", str1, "$6$X8jRqUQt$f4Uob5BOcMuwkXZodo8Ty80pd9AGfD0SQU0ibBjhdzbAyytXiKp.EmPT5SJ5FZE43YRXQiuc3RDQpgAiznTFq/");
    }

    @Test
    public void test0191() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0191");
        byte[] byteArray0 = null;
        byte[] byteArray6 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray6);
        java.lang.String str9 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray6, "99448658175a0534e08dbca1fe67b58231a53eec");
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray10 = org.apache.commons.codec.digest.Blake3.keyedHash(byteArray0, byteArray6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str7, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str9, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
    }

    @Test
    public void test0192() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0192");
        java.nio.charset.Charset charset0 = null;
        java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset(charset0);
        org.apache.commons.codec.binary.Hex hex2 = new org.apache.commons.codec.binary.Hex(charset1);
        java.nio.ByteBuffer byteBuffer4 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = hex2.decode(byteBuffer4);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Odd number of characters.");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset1);
        org.junit.Assert.assertNotNull(byteBuffer4);
    }

    @Test
    public void test0193() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0193");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0194() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0194");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        java.io.File file2 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray3 = digestUtils1.digest(file2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0195() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0195");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream4 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base64OutputStream1);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream7 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base64OutputStream1, true, false);
        org.junit.Assert.assertNotNull(outputStream0);
    }

    @Test
    public void test0196() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0196");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.math.BigInteger bigInteger1 = org.apache.commons.codec.binary.Base64.decodeInteger(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0197() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0197");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        org.apache.commons.codec.net.PercentCodec percentCodec15 = new org.apache.commons.codec.net.PercentCodec(byteArray5, true);
        int int16 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        org.junit.Assert.assertTrue("'" + int16 + "' != '" + 760066800 + "'", int16 == 760066800);
    }

    @Test
    public void test0198() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0198");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        java.lang.String str4 = soundex2.soundex("01360240043788015936020505");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "" + "'", str4, "");
    }

    @Test
    public void test0199() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0199");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("50d099290876d18e40b67f38cde88ecd91b8d6b69c349dc179b209e2", "SHA-224");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[18, 85, -80, 70, -81, -31, 17, 76, -107, -124, 115, 50, -27, -97, 76, -48, 63, 27, 16, 12, 75, -3, -41, 119, -74, -15, 23, 77, -36, 90, -122, -67]");
    }

    @Test
    public void test0200() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0200");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        boolean boolean4 = base16InputStream3.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            long long6 = base16InputStream3.skip((long) (short) -1);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Negative skip length: -1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
    }

    @Test
    public void test0201() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0201");
        org.apache.commons.codec.digest.UnixCrypt unixCrypt0 = new org.apache.commons.codec.digest.UnixCrypt();
    }

    @Test
    public void test0202() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0202");
        org.apache.commons.codec.digest.HmacUtils hmacUtils0 = new org.apache.commons.codec.digest.HmacUtils();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = hmacUtils0.hmac(file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0203() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0203");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha("AAAAAAA");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray4);
        byte[] byteArray7 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray4);
        java.lang.String str8 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray4);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.keyedHash(byteArray1, byteArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-7, -78, -122, -99, -26, -52, -110, 38, -71, -112, -40, 63, -128, 94, -56, 57, 21, -52, -100, -123]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "" + "'", str8, "");
    }

    @Test
    public void test0204() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0204");
        java.io.InputStream inputStream0 = java.io.InputStream.nullInputStream();
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream0);
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream0);
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            int int9 = inputStream0.readNBytes(byteArray5, 10, 760066800);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: Range [10, 10 + 760066800) out of bounds for length 1");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(inputStream0);
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str1, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str2, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
    }

    @Test
    public void test0205() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0205");
        byte[] byteArray0 = null;
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream2);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream2);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray6 = org.apache.commons.codec.digest.HmacUtils.hmacMd5(byteArray0, inputStream2);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Null key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
    }

    @Test
    public void test0206() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0206");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        byte[] byteArray8 = uRLCodec1.decode(byteArray5);
        byte[] byteArray9 = null;
        byte[] byteArray10 = uRLCodec1.decode(byteArray9);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str13 = uRLCodec1.decode("2165db20acc1d22d51a2f5bca7f209b5b91f769c0d308cfb7a2a99decb9eee2089892bbbb00c17c39df479ed8a7396de6f6d3448da7850231eab0c9c871b6952", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0207() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0207");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Hex hex1 = new org.apache.commons.codec.binary.Hex("=?UTF-8?B?U0hBLTIyNA==?=");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: =?UTF-8?B?U0hBLTIyNA==?=");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0208() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0208");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        boolean boolean4 = base16InputStream3.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = base16InputStream3.readAllBytes();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
    }

    @Test
    public void test0209() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0209");
        byte[] byteArray0 = null;
        char[] charArray1 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray0);
        org.junit.Assert.assertNotNull(charArray1);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray1), "");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray1), "");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray1), "[]");
    }

    @Test
    public void test0210() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0210");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.lang.String str15 = quotedPrintableCodec1.getDefaultCharset();
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        byte[] byteArray17 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream16);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj18 = quotedPrintableCodec1.encode((java.lang.Object) inputStream16);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type java.io.InputStream$1 cannot be quoted-printable encoded");
        } catch (org.apache.commons.codec.EncoderException e) {
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
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "UTF-8" + "'", str15, "UTF-8");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
    }

    @Test
    public void test0211() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0211");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("SHA3-512");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + true + "'", boolean1 == true);
    }

    @Test
    public void test0212() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0212");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        byte[] byteArray9 = uRLCodec1.decode(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str11 = org.apache.commons.codec.digest.Crypt.crypt(byteArray9, "\u42f9\u0892\u952a\ub7ae\ua633\u8e61\uf18c\ud06d\u8bd7\u0336\u064f\u36cd\u22c8\u5b3c");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: ??????????????????");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$1$0BTnAs3F$R4SXlD5orEZvLEz605pCH/" + "'", str8, "$1$0BTnAs3F$R4SXlD5orEZvLEz605pCH/");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0]");
    }

    @Test
    public void test0213() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0213");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        boolean boolean1 = beiderMorseEncoder0.isConcat();
        org.apache.commons.codec.language.bm.NameType nameType2 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType3 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet4 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap5 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType2, ruleType3, languageSet4);
        // The following exception was thrown during execution in test generation
        try {
            beiderMorseEncoder0.setRuleType(ruleType3);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: ruleType must not be RULES");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + true + "'", boolean1 == true);
        org.junit.Assert.assertTrue("'" + nameType2 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType2.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet4);
        org.junit.Assert.assertNotNull(strMap5);
    }

    @Test
    public void test0214() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0214");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_384;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-384" + "'", str0, "SHA-384");
    }

    @Test
    public void test0215() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0215");
        byte[] byteArray0 = null;
        java.lang.String str1 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray0);
        org.junit.Assert.assertNull(str1);
    }

    @Test
    public void test0216() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0216");
        byte[] byteArray0 = null;
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream2);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.digest.HmacUtils.hmacSha1(byteArray0, inputStream2);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Null key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    public void test0217() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0217");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.NameType nameType2 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang3 = org.apache.commons.codec.language.bm.Lang.instance(nameType2);
        org.apache.commons.codec.language.bm.NameType nameType4 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType5 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap7 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType4, ruleType5, languageSet6);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet8 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap9 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType2, ruleType5, languageSet8);
        // The following exception was thrown during execution in test generation
        try {
            java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap11 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType5, "01230120022455012623010202");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: No rules found for ash, rules, 01230120022455012623010202.");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertTrue("'" + nameType2 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType2.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang3);
        org.junit.Assert.assertTrue("'" + nameType4 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType4.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType5 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType5.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet6);
        org.junit.Assert.assertNotNull(strMap7);
        org.junit.Assert.assertNotNull(languageSet8);
        org.junit.Assert.assertNotNull(strMap9);
    }

    @Test
    public void test0218() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0218");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        qCodec3.setEncodeBlanks(true);
        java.lang.String str7 = qCodec3.encode("\000\000\000\000\000");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = qCodec3.decode("UTF-8");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: RFC 1522 violation: malformed encoded content");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "=?UTF-8?Q?=00=00=00=00=00?=" + "'", str7, "=?UTF-8?Q?=00=00=00=00=00?=");
    }

    @Test
    public void test0219() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0219");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        base64InputStream5.close();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex((java.io.InputStream) base64InputStream5);
            org.junit.Assert.fail("Expected exception of type java.io.IOException; message: Stream closed");
        } catch (java.io.IOException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    public void test0220() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0220");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType5 = phoneticEngine4.getRuleType();
        org.apache.commons.codec.language.bm.Lang lang6 = phoneticEngine4.getLang();
        int int7 = phoneticEngine4.getMaxPhonemes();
        int int8 = phoneticEngine4.getMaxPhonemes();
        int int9 = phoneticEngine4.getMaxPhonemes();
        org.apache.commons.codec.language.bm.RuleType ruleType10 = phoneticEngine4.getRuleType();
        org.junit.Assert.assertNull(ruleType5);
        org.junit.Assert.assertNull(lang6);
        org.junit.Assert.assertTrue("'" + int7 + "' != '" + (-1) + "'", int7 == (-1));
        org.junit.Assert.assertTrue("'" + int8 + "' != '" + (-1) + "'", int8 == (-1));
        org.junit.Assert.assertTrue("'" + int9 + "' != '" + (-1) + "'", int9 == (-1));
        org.junit.Assert.assertNull(ruleType10);
    }

    @Test
    public void test0221() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0221");
        java.io.InputStream inputStream0 = null;
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy5 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream6 = new org.apache.commons.codec.binary.Base32InputStream(inputStream0, true, (int) (byte) 0, byteArray4, codecPolicy5);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms7 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet8 = null;
        byte[] byteArray10 = new byte[] { (byte) 100 };
        byte[] byteArray11 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet8, byteArray10);
        byte[] byteArray12 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray11);
        javax.crypto.Mac mac13 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms7, byteArray12);
        org.apache.commons.codec.digest.HmacUtils hmacUtils15 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms7, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream16 = null;
        byte[] byteArray20 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy21 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream22 = new org.apache.commons.codec.binary.Base32InputStream(inputStream16, true, (int) (byte) 0, byteArray20, codecPolicy21);
        char[] charArray23 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray20);
        java.lang.String str24 = hmacUtils15.hmacHex(byteArray20);
        // The following exception was thrown during execution in test generation
        try {
            int int27 = base32InputStream6.readNBytes(byteArray20, (int) '4', (-1));
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: Range [52, 52 + -1) out of bounds for length 28");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy5 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy5.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertTrue("'" + hmacAlgorithms7 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms7.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[100]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[100]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac13);
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy21 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy21.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray23);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray23), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray23), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray23), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str24, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
    }

    @Test
    public void test0222() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0222");
        java.lang.String str2 = org.apache.commons.codec.digest.Crypt.crypt("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "d7bXONth0AIyo" + "'", str2, "d7bXONth0AIyo");
    }

    @Test
    public void test0223() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0223");
        java.security.MessageDigest messageDigest0 = null;
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream1);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, inputStream1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str2, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }

    @Test
    public void test0224() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0224");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex("202501fe2df741220d38e4ee0487ef0aae4dbf81ea9af5e7ccb75d0eba0c5591b27fd090e0ef62e26c5813d21bf9ce1f1bb3b28da49a1b4996abb8defa283943");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "75d677f8d09e1a72339a45a86a075588b520e71f5bc6f44ef24d75869461e866a352ed4bda9fa03c4cc7f14eec2c67127e61b5cc98514297f19920502c5b4bc5" + "'", str1, "75d677f8d09e1a72339a45a86a075588b520e71f5bc6f44ef24d75869461e866a352ed4bda9fa03c4cc7f14eec2c67127e61b5cc98514297f19920502c5b4bc5");
    }

    @Test
    public void test0225() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0225");
        java.lang.String str2 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt("8350e5a3e24c153df2275c9f80692773", "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "$apr1$0a6d29eb$88F7hdkOqgQi8ZTrHQlZN0" + "'", str2, "$apr1$0a6d29eb$88F7hdkOqgQi8ZTrHQlZN0");
    }

    @Test
    public void test0226() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0226");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.NameType nameType2 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang3 = org.apache.commons.codec.language.bm.Lang.instance(nameType2);
        org.apache.commons.codec.language.bm.NameType nameType4 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType5 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap7 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType4, ruleType5, languageSet6);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet8 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap9 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType2, ruleType5, languageSet8);
        // The following exception was thrown during execution in test generation
        try {
            java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap11 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType5, "d2789eba1651444e3ee6cb80db8900fa");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: No rules found for gen, rules, d2789eba1651444e3ee6cb80db8900fa.");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertTrue("'" + nameType2 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType2.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang3);
        org.junit.Assert.assertTrue("'" + nameType4 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType4.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType5 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType5.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet6);
        org.junit.Assert.assertNotNull(strMap7);
        org.junit.Assert.assertNotNull(languageSet8);
        org.junit.Assert.assertNotNull(strMap9);
    }

    @Test
    public void test0227() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0227");
        java.nio.charset.Charset charset0 = null;
        java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset(charset0);
        org.apache.commons.codec.binary.Hex hex2 = new org.apache.commons.codec.binary.Hex(charset1);
        java.lang.String str3 = hex2.getCharsetName();
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        byte[] byteArray9 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray7);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray10 = hex2.decode(byteArray7);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Odd number of characters.");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset1);
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "UTF-8" + "'", str3, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[48, 49, 49, 48, 48, 49, 48, 48]");
    }

    @Test
    public void test0228() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0228");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.RULES;
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet2 = org.apache.commons.codec.language.bm.Languages.ANY_LANGUAGE;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap3 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType1, languageSet2);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = languageSet2.getAny();
            org.junit.Assert.fail("Expected exception of type java.util.NoSuchElementException; message: Can't fetch any language from the any language set.");
        } catch (java.util.NoSuchElementException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.RULES + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.RULES));
        org.junit.Assert.assertNotNull(languageSet2);
        org.junit.Assert.assertNotNull(strMap3);
    }

    @Test
    public void test0229() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0229");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray4);
        xXHash32_0.update(byteArray6, (int) (byte) 10, (-690116322));
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray6);
        org.apache.commons.codec.net.PercentCodec percentCodec12 = new org.apache.commons.codec.net.PercentCodec(byteArray6, false);
        org.apache.commons.codec.language.Soundex soundex13 = new org.apache.commons.codec.language.Soundex();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj14 = percentCodec12.encode((java.lang.Object) soundex13);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type org.apache.commons.codec.language.Soundex cannot be Percent encoded");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[-105, 58, 108, -60, 23, -121, 77, -3, 127, -30, -36, 64, -9, 119, 6, -49, 25, 62, -50, -58, 83, 123, -61, -47, -58, 26, -34, -5, -74, -87, -109, 72]");
    }

    @Test
    public void test0230() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0230");
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
        java.io.InputStream inputStream33 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream36 = new org.apache.commons.codec.binary.Base16InputStream(inputStream33, true, true);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray37 = hmacUtils32.hmac((java.io.InputStream) base16InputStream36);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0231() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0231");
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
        org.apache.commons.codec.net.URLCodec uRLCodec20 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet21 = null;
        byte[] byteArray23 = new byte[] { (byte) 100 };
        byte[] byteArray24 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet21, byteArray23);
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray24);
        byte[] byteArray26 = uRLCodec20.encode(byteArray25);
        int int27 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray25);
        byte[] byteArray28 = quotedPrintableCodec1.encode(byteArray25);
        byte[] byteArray29 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray28);
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
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[100]");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[100]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertTrue("'" + int27 + "' != '" + (-690116322) + "'", int27 == (-690116322));
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[70, 104, 61, 56, 57, 118, 61, 56, 50, 61, 67, 67, 61, 68, 50, 61, 66, 49, 61, 69, 69, 61, 48, 67, 61, 65, 69, 61, 56, 68, 61, 67, 53, 89, 71, 41, 61, 49, 70, 61, 56, 49, 61, 57, 67, 61, 67, 53, 61, 57, 69, 61, 69, 49, 38, 61, 70, 53, 61, 66, 68, 36, 59, 61, 49, 56, 82, 87, 116, 61, 49, 52, 65, 61, 13, 10, 58, 61, 69, 69, 61, 68, 53, 120, 61, 48, 66, 95, 61, 66, 49, 61, 49, 48, 61, 57, 48, 61, 48, 51, 61, 56, 55, 61, 49, 53, 61, 66, 69, 61, 69, 68, 61, 49, 66, 61, 48, 48, 113, 74, 61, 49, 53, 61, 66, 51, 61, 49, 67, 61, 56, 68, 61, 57, 54, 116, 61, 70, 66, 61, 68, 66, 61, 68, 70, 61, 55, 70, 61, 68, 52, 61, 13, 10, 61, 49, 57, 61, 49, 67]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[98, -93, -76, -118, -40, 33, 106, 49, -21, -79, 96, -30, 111, 68, -88, -67, -79, -56, 111, -93, 105, -24, 45, -28, -118, 43, 117, 90]");
    }

    @Test
    public void test0232() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0232");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        boolean boolean8 = base32_1.isInAlphabet(byteArray6, false);
        byte[] byteArray10 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str11 = base32_1.encodeAsString(byteArray10);
        java.math.BigInteger bigInteger12 = org.apache.commons.codec.binary.Base64.decodeInteger(byteArray10);
        // The following exception was thrown during execution in test generation
        try {
            long long16 = org.apache.commons.codec.digest.MurmurHash3.hash64(byteArray10, (int) (short) 10, (int) '#', (int) (byte) -1);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 10 out of bounds for length 6");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
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
        org.junit.Assert.assertNotNull(bigInteger12);
    }

    @Test
    public void test0233() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0233");
        java.nio.charset.Charset charset0 = null;
        java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset(charset0);
        org.apache.commons.codec.binary.Hex hex2 = new org.apache.commons.codec.binary.Hex(charset1);
        java.lang.String str3 = hex2.toString();
        java.io.OutputStream outputStream4 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream5 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream4);
        byte[] byteArray8 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        base64OutputStream5.write(byteArray8);
        byte[] byteArray12 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str13 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray12);
        java.lang.String str14 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray8, byteArray12);
        byte[] byteArray15 = hex2.encode(byteArray8);
        // The following exception was thrown during execution in test generation
        try {
            int int18 = org.apache.commons.codec.digest.MurmurHash2.hash32(byteArray8, (int) (byte) -1, (int) (short) 0);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -2 out of bounds for length 32");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset1);
        org.junit.Assert.assertNotNull(outputStream4);
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "\000\ufffd" + "'", str13, "\000\ufffd");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3" + "'", str14, "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[101, 54, 97, 55, 102, 100, 55, 99, 48, 51, 52, 53, 54, 99, 57, 101, 53, 53, 100, 51, 49, 99, 50, 52, 57, 55, 55, 56, 53, 54, 52, 52, 49, 100, 52, 53, 57, 102, 48, 97, 102, 102, 50, 98, 56, 50, 51, 101, 48, 50, 53, 51, 50, 98, 56, 100, 52, 53, 97, 100, 48, 52, 51, 102]");
    }

    @Test
    public void test0234() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0234");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        org.apache.commons.codec.net.URLCodec uRLCodec3 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray7);
        byte[] byteArray10 = uRLCodec3.decode(byteArray7);
        byte[] byteArray11 = null;
        byte[] byteArray12 = uRLCodec3.decode(byteArray11);
        byte[] byteArray18 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str19 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray18);
        java.lang.String str21 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray18, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_22 = new org.apache.commons.codec.binary.Base16();
        boolean boolean24 = base16_22.isInAlphabet("AAAAAAA");
        byte[] byteArray28 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str30 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray28, true);
        java.lang.String str31 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray28);
        boolean boolean33 = base16_22.isInAlphabet(byteArray28, true);
        byte[] byteArray34 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray18, byteArray28);
        byte[] byteArray35 = uRLCodec3.encode(byteArray34);
        java.security.MessageDigest messageDigest36 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteArray34);
        java.lang.String str37 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray34);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str9, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[100]");
        org.junit.Assert.assertNull(byteArray12);
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str19, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str21, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean24 + "' != '" + true + "'", boolean24 == true);
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "ffffff" + "'", str30, "ffffff");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str31, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean33 + "' != '" + false + "'", boolean33 == false);
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
        org.junit.Assert.assertNotNull(messageDigest36);
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA3-224 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertEquals("'" + str37 + "' != '" + "HXRVYJ3rI5njqeid9obvIItpLUW+F9LijCHabojojS4=" + "'", str37, "HXRVYJ3rI5njqeid9obvIItpLUW+F9LijCHabojojS4=");
    }

    @Test
    public void test0235() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0235");
        org.apache.commons.codec.binary.Base64 base64_1 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        boolean boolean2 = base64_1.isStrictDecoding();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils4 = new org.apache.commons.codec.digest.DigestUtils(messageDigest3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj5 = base64_1.decode((java.lang.Object) digestUtils4);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Parameter supplied to Base-N decode is not a byte[] or a String");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + false + "'", boolean2 == false);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0236() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0236");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        java.lang.String str8 = bCodec2.getDefaultCharset();
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C9 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C9.reset();
        java.util.BitSet bitSet11 = null;
        byte[] byteArray13 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray14 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet11, byteArray13);
        java.lang.String str15 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray13);
        pureJavaCrc32C9.update(byteArray13, (-690116322), (-1612190696));
        byte[] byteArray20 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray21 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray20);
        pureJavaCrc32C9.update(byteArray20);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj23 = bCodec2.decode((java.lang.Object) pureJavaCrc32C9);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type org.apache.commons.codec.digest.PureJavaCrc32C cannot be decoded using BCodec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "UTF-8" + "'", str8, "UTF-8");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[]");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str15, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
    }

    @Test
    public void test0237() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0237");
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
        byte[] byteArray35 = hmacUtils32.hmac(byteBuffer34);
        java.util.Random random36 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str37 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray35, random36);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
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
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[-56, -6, 38, 92, -40, -35, -88, -80, -32, 55, -47, -60, -40, 18, -70, 57, -127, -91, 121, -38, -55, 108, 76, -109, -12, 40, 123, -90]");
    }

    @Test
    public void test0238() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0238");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", false);
        int int3 = soundex2.getMaxLength();
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + 4 + "'", int3 == 4);
    }

    @Test
    public void test0239() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0239");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA3_224;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA3-224" + "'", str0, "SHA3-224");
    }

    @Test
    public void test0240() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0240");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0241() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0241");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        byte[] byteArray9 = uRLCodec1.decode(byteArray5);
        byte[] byteArray15 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray15);
        java.lang.String str18 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray15, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str19 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray15);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray15);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray15);
        java.lang.String str22 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray15);
        byte[] byteArray23 = uRLCodec1.decode(byteArray15);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str26 = uRLCodec1.encode("MD2", "6IiiRyxmjcARw");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: 6IiiRyxmjcARw");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$1$PQMr.9Sp$PR06G./ZjqvntU.vSuyLI1" + "'", str8, "$1$PQMr.9Sp$PR06G./ZjqvntU.vSuyLI1");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str16, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str18, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "AAAAAAA" + "'", str19, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str20, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str21, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "\000\000\000\000\000" + "'", str22, "\000\000\000\000\000");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[0, 0, 0, 0, 0]");
    }

    @Test
    public void test0242() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0242");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.Lang lang2 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet4 = lang2.guessLanguages("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertNotNull(lang2);
        org.junit.Assert.assertNotNull(languageSet4);
    }

    @Test
    public void test0243() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0243");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        java.io.InputStream inputStream5 = java.io.InputStream.nullInputStream();
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream5);
        java.lang.String str8 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream5);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray2, "rules");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str6, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str7, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str8, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1" + "'", str10, "$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1");
    }

    @Test
    public void test0244() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0244");
        java.io.OutputStream outputStream0 = null;
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream3 = new org.apache.commons.codec.binary.Base16OutputStream(outputStream0, false, false);
        byte[] byteArray7 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray8 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray7);
        java.io.InputStream inputStream9 = java.io.InputStream.nullInputStream();
        java.lang.String str10 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray8, inputStream9);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream11 = new org.apache.commons.codec.binary.Base64InputStream(inputStream9);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream11);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream11);
        byte[] byteArray14 = org.apache.commons.codec.digest.DigestUtils.sha384((java.io.InputStream) base64InputStream11);
        org.apache.commons.codec.binary.Base64 base64_17 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy18 = base64_17.getCodecPolicy();
        org.apache.commons.codec.binary.Base16 base16_19 = new org.apache.commons.codec.binary.Base16(false, codecPolicy18);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64OutputStream base64OutputStream20 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base16OutputStream3, true, (int) (byte) 100, byteArray14, codecPolicy18);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [8?`?Q??8L?2~???j!??????CL???c???'N??oe?????H??[]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream9);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str10, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str12, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str13, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertTrue("'" + codecPolicy18 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy18.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test0245() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0245");
        byte[] byteArray0 = null;
        java.lang.String str1 = org.apache.commons.codec.binary.BinaryCodec.toAsciiString(byteArray0);
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "" + "'", str1, "");
    }

    @Test
    public void test0246() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0246");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((byte) 100);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: pad must not be in alphabet or whitespace");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0247() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0247");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream5 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.digest.XXHash32 xXHash32_8 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet9 = null;
        byte[] byteArray11 = new byte[] { (byte) 100 };
        byte[] byteArray12 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet9, byteArray11);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray12);
        byte[] byteArray14 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray12);
        xXHash32_8.update(byteArray14, (int) (byte) 10, (-690116322));
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream18 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true, 760066800, byteArray14);
        base32OutputStream18.eof();
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[100]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[100]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[48, 49, 49, 48, 48, 49, 48, 48]");
    }

    @Test
    public void test0248() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0248");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        int int16 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray5, 4, (int) '#');
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.Blake3 blake3_17 = org.apache.commons.codec.digest.Blake3.initKeyedHash(byteArray5);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
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
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        org.junit.Assert.assertTrue("'" + int16 + "' != '" + 1650246903 + "'", int16 == 1650246903);
    }

    @Test
    public void test0249() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0249");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("AAAAAAA");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$Do52jlNc$xakHCbK/kV4Fl5RNTztk6W2Qddt6ALNIcBzaauoh1UFpoahIm36hIhGxtiP3k3aF.XM6TNoCQN8huleOEIG2e." + "'", str1, "$6$Do52jlNc$xakHCbK/kV4Fl5RNTztk6W2Qddt6ALNIcBzaauoh1UFpoahIm36hIhGxtiP3k3aF.XM6TNoCQN8huleOEIG2e.");
    }

    @Test
    public void test0250() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0250");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64(0L);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + (-8620514229188030809L) + "'", long1 == (-8620514229188030809L));
    }

    @Test
    public void test0251() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0251");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj5 = qCodec3.decode((java.lang.Object) "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: RFC 1522 violation: malformed encoded content");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
    }

    @Test
    public void test0252() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0252");
        org.apache.commons.codec.binary.Base64 base64_1 = new org.apache.commons.codec.binary.Base64(0);
        boolean boolean2 = base64_1.isUrlSafe();
        boolean boolean3 = base64_1.isStrictDecoding();
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + false + "'", boolean2 == false);
        org.junit.Assert.assertTrue("'" + boolean3 + "' != '" + false + "'", boolean3 == false);
    }

    @Test
    public void test0253() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0253");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        base64InputStream5.close();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.shaHex((java.io.InputStream) base64InputStream5);
            org.junit.Assert.fail("Expected exception of type java.io.IOException; message: Stream closed");
        } catch (java.io.IOException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    public void test0254() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0254");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray5 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet2, byteArray4);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray4);
        pureJavaCrc32C0.update(byteArray4, (-690116322), (-1612190696));
        java.math.BigInteger bigInteger10 = org.apache.commons.codec.binary.Base64.decodeInteger(byteArray4);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str6, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(bigInteger10);
    }

    @Test
    public void test0255() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0255");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex("c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "c6699c7aa4c4899a7838b6472b6ae7719eda306fc3de2abefd814d5909c178da" + "'", str1, "c6699c7aa4c4899a7838b6472b6ae7719eda306fc3de2abefd814d5909c178da");
    }

    @Test
    public void test0256() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0256");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_224("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        java.lang.String str3 = org.apache.commons.codec.binary.StringUtils.newStringUtf16Le(byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            javax.crypto.Mac mac4 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac("d7bXONth0AIyo", byteArray2);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm d7bXONth0AIyo not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-7, 66, -110, 8, 42, -107, -82, -73, 51, -90, 97, -114, -116, -15, 109, -48, -41, -117, 54, 3, 79, 6, -51, 54, -56, 34, 60, 91]");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "\u42f9\u0892\u952a\ub7ae\ua633\u8e61\uf18c\ud06d\u8bd7\u0336\u064f\u36cd\u22c8\u5b3c" + "'", str3, "\u42f9\u0892\u952a\ub7ae\ua633\u8e61\uf18c\ud06d\u8bd7\u0336\u064f\u36cd\u22c8\u5b3c");
    }

    @Test
    public void test0257() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0257");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec("c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0258() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0258");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        java.lang.String[] strArray41 = new java.lang.String[] { "ffffff", "663b90c899fa25a111067be0c22ffc64dcf581c2", "SHA-224", "0Acd8L3u4hVxI", "UTF-16LE", "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "2ef0725975afd171e9cb76444b4969c3", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "ffffff", "6IiiRyxmjcARw", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "0A01640101", "2ef0725975afd171e9cb76444b4969c3", "663b90c899fa25a111067be0c22ffc64dcf581c2", "", "ffffff", "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", "c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff", "6IiiRyxmjcARw", "663b90c899fa25a111067be0c22ffc64dcf581c2", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "MD2", "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "99448658175a0534e08dbca1fe67b58231a53eec", "0A01640101", "0A01640101", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "SHA3-256", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107", "", "663b90c899fa25a111067be0c22ffc64dcf581c2", "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" };
        java.util.LinkedHashSet<java.lang.String> strSet42 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean43 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet42, strArray41);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet44 = org.apache.commons.codec.language.bm.Languages.LanguageSet.from((java.util.Set<java.lang.String>) strSet42);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj45 = soundex2.encode((java.lang.Object) languageSet44);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Soundex encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(strArray41);
        org.junit.Assert.assertTrue("'" + boolean43 + "' != '" + true + "'", boolean43 == true);
        org.junit.Assert.assertNotNull(languageSet44);
    }

    @Test
    public void test0259() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0259");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_512((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0260() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0260");
        int int0 = org.apache.commons.codec.binary.BaseNCodec.MIME_CHUNK_SIZE;
        org.junit.Assert.assertTrue("'" + int0 + "' != '" + 76 + "'", int0 == 76);
    }

    @Test
    public void test0261() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0261");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91" + "'", str1, "2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91");
    }

    @Test
    public void test0262() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0262");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0263() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0263");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: ");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0264() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0264");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            int int7 = soundex4.difference("\000\ufffd", "=?UTF-16LE?Q?=00=00=FD=FF?=");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: The character is not mapped: U (index=20)");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0265() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0265");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray2);
        byte[] byteArray5 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5, "0Ac7cg1i0oNqE", "\000\000\000\000\000");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 0Ac7cg1i0oNqE");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str4, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
    }

    @Test
    public void test0266() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0266");
        org.apache.commons.codec.language.Nysiis nysiis1 = new org.apache.commons.codec.language.Nysiis(true);
        org.apache.commons.codec.net.URLCodec uRLCodec3 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray7);
        byte[] byteArray10 = uRLCodec3.decode(byteArray7);
        byte[] byteArray11 = null;
        byte[] byteArray12 = uRLCodec3.decode(byteArray11);
        java.lang.String str13 = uRLCodec3.getDefaultCharset();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj14 = nysiis1.encode((java.lang.Object) uRLCodec3);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Nysiis encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str9, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[100]");
        org.junit.Assert.assertNull(byteArray12);
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "hi!" + "'", str13, "hi!");
    }

    @Test
    public void test0267() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0267");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj2 = beiderMorseEncoder0.encode((java.lang.Object) messageDigest1);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: BeiderMorseEncoder encode parameter is not of type String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "MD2 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0268() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0268");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        java.lang.String str8 = bCodec2.getDefaultCharset();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str10 = bCodec2.decode("6e57afa9a4816afe502bfa9a045f02ee2bab5660");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: RFC 1522 violation: malformed encoded content");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "UTF-8" + "'", str8, "UTF-8");
    }

    @Test
    public void test0269() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0269");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        boolean boolean8 = base32_1.isInAlphabet(byteArray6, false);
        java.util.Random random10 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str11 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray6, "9b9e60058fae476c9ee6ef8fc698d89e", random10);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 9b9e60058fae476c9ee6ef8fc698d89e");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean8 + "' != '" + false + "'", boolean8 == false);
    }

    @Test
    public void test0270() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0270");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_512_224;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-512/224" + "'", str0, "SHA-512/224");
    }

    @Test
    public void test0271() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0271");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64((byte) -1);
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0272() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0272");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex("org.apache.commons.codec.EncoderException");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "b29f8a352ed4b801dd66c530b4838ecdb3d500668d794fcd935a8b6f5d3a0daf38890a5bd65f5a49abfe8bbb8eedeedaf57a14baa3b3976e07182235c979aa9d" + "'", str1, "b29f8a352ed4b801dd66c530b4838ecdb3d500668d794fcd935a8b6f5d3a0daf38890a5bd65f5a49abfe8bbb8eedeedaf57a14baa3b3976e07182235c979aa9d");
    }

    @Test
    public void test0273() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0273");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Le("MD5");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[77, 0, 68, 0, 53, 0]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6" + "'", str2, "728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6");
    }

    @Test
    public void test0274() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0274");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec0 = new org.apache.commons.codec.net.QuotedPrintableCodec();
    }

    @Test
    public void test0275() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0275");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5;
        org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "UTF-8");
        java.io.File file3 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = hmacUtils2.hmacHex(file3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_MD5));
    }

    @Test
    public void test0276() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0276");
        org.apache.commons.codec.language.DaitchMokotoffSoundex daitchMokotoffSoundex1 = new org.apache.commons.codec.language.DaitchMokotoffSoundex(false);
        java.lang.String str3 = daitchMokotoffSoundex1.encode("SHA-512/256");
        java.lang.String str5 = daitchMokotoffSoundex1.soundex("\000\ufffd");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "400000" + "'", str3, "400000");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "000000" + "'", str5, "000000");
    }

    @Test
    public void test0277() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0277");
        int int3 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) 64, (long) 1, 100);
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + (-1621933077) + "'", int3 == (-1621933077));
    }

    @Test
    public void test0278() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0278");
        org.apache.commons.codec.digest.Sha2Crypt sha2Crypt0 = new org.apache.commons.codec.digest.Sha2Crypt();
    }

    @Test
    public void test0279() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0279");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("BTFT");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "78fdcba5ae892b088edbc0748cc2e854ff72cc2a6ea008870b1da380" + "'", str1, "78fdcba5ae892b088edbc0748cc2e854ff72cc2a6ea008870b1da380");
    }

    @Test
    public void test0280() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0280");
        org.apache.commons.codec.language.Metaphone metaphone0 = new org.apache.commons.codec.language.Metaphone();
        org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(false);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj3 = metaphone0.encode((java.lang.Object) base16_2);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Metaphone encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0281() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0281");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex("Ae3f");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "07839f3f2ce2a945c4636a0413fb83722520cb1d91a271db0609aa223b2c0edb" + "'", str1, "07839f3f2ce2a945c4636a0413fb83722520cb1d91a271db0609aa223b2c0edb");
    }

    @Test
    public void test0282() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0282");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = bCodec2.decode("728e7e7fe175a32ac1c5fa6786a0ca765daf419e5b76f5e89f105b541267b7a6");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: RFC 1522 violation: malformed encoded content");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
    }

    @Test
    public void test0283() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0283");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("78fdcba5ae892b088edbc0748cc2e854ff72cc2a6ea008870b1da380");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "5981d4f7892cfca9e4089cf1f1b8423bc7b33e98a0d594757ac8dd55" + "'", str1, "5981d4f7892cfca9e4089cf1f1b8423bc7b33e98a0d594757ac8dd55");
    }

    @Test
    public void test0284() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0284");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.binary.Hex.decodeHex(charArray3);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Odd number of characters.");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
    }

    @Test
    public void test0285() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0285");
        org.apache.commons.codec.digest.DigestUtils digestUtils0 = new org.apache.commons.codec.digest.DigestUtils();
        java.nio.file.Path path1 = null;
        java.nio.file.OpenOption openOption2 = null;
        java.nio.file.OpenOption[] openOptionArray3 = new java.nio.file.OpenOption[] { openOption2 };
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = digestUtils0.digest(path1, openOptionArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(openOptionArray3);
    }

    @Test
    public void test0286() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0286");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        qCodec3.setEncodeBlanks(true);
        java.lang.String str7 = qCodec3.encode("\000\000\000\000\000");
        java.nio.charset.Charset charset9 = org.apache.commons.codec.Charsets.UTF_16LE;
        java.lang.String str10 = qCodec3.encode("\000\ufffd", charset9);
        java.lang.Throwable throwable11 = null;
        org.apache.commons.codec.DecoderException decoderException12 = new org.apache.commons.codec.DecoderException(throwable11);
        org.apache.commons.codec.EncoderException encoderException13 = new org.apache.commons.codec.EncoderException();
        decoderException12.addSuppressed((java.lang.Throwable) encoderException13);
        java.lang.Throwable throwable15 = null;
        org.apache.commons.codec.DecoderException decoderException16 = new org.apache.commons.codec.DecoderException(throwable15);
        org.apache.commons.codec.EncoderException encoderException17 = new org.apache.commons.codec.EncoderException();
        decoderException16.addSuppressed((java.lang.Throwable) encoderException17);
        encoderException13.addSuppressed((java.lang.Throwable) encoderException17);
        java.lang.Throwable[] throwableArray20 = encoderException13.getSuppressed();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj21 = qCodec3.decode((java.lang.Object) throwableArray20);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type [Ljava.lang.Throwable; cannot be decoded using Q codec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "=?UTF-8?Q?=00=00=00=00=00?=" + "'", str7, "=?UTF-8?Q?=00=00=00=00=00?=");
        org.junit.Assert.assertNotNull(charset9);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "=?UTF-16LE?Q?=00=00=FD=FF?=" + "'", str10, "=?UTF-16LE?Q?=00=00=FD=FF?=");
        org.junit.Assert.assertNotNull(throwableArray20);
    }

    @Test
    public void test0287() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0287");
        java.lang.Throwable throwable1 = null;
        org.apache.commons.codec.DecoderException decoderException2 = new org.apache.commons.codec.DecoderException(throwable1);
        org.apache.commons.codec.EncoderException encoderException3 = new org.apache.commons.codec.EncoderException();
        decoderException2.addSuppressed((java.lang.Throwable) encoderException3);
        java.lang.Throwable throwable5 = null;
        org.apache.commons.codec.DecoderException decoderException6 = new org.apache.commons.codec.DecoderException(throwable5);
        org.apache.commons.codec.EncoderException encoderException7 = new org.apache.commons.codec.EncoderException();
        decoderException6.addSuppressed((java.lang.Throwable) encoderException7);
        encoderException3.addSuppressed((java.lang.Throwable) encoderException7);
        java.lang.Throwable[] throwableArray10 = encoderException7.getSuppressed();
        org.apache.commons.codec.DecoderException decoderException11 = new org.apache.commons.codec.DecoderException((java.lang.Throwable) encoderException7);
        org.apache.commons.codec.EncoderException encoderException12 = new org.apache.commons.codec.EncoderException("49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6", (java.lang.Throwable) decoderException11);
        org.apache.commons.codec.EncoderException encoderException13 = new org.apache.commons.codec.EncoderException((java.lang.Throwable) decoderException11);
        java.lang.String str14 = decoderException11.toString();
        org.junit.Assert.assertNotNull(throwableArray10);
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "org.apache.commons.codec.DecoderException: org.apache.commons.codec.EncoderException" + "'", str14, "org.apache.commons.codec.DecoderException: org.apache.commons.codec.EncoderException");
    }

    @Test
    public void test0288() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0288");
        long long3 = org.apache.commons.codec.digest.MurmurHash2.hash64("202501fe2df741220d38e4ee0487ef0aae4dbf81ea9af5e7ccb75d0eba0c5591b27fd090e0ef62e26c5813d21bf9ce1f1bb3b28da49a1b4996abb8defa283943", 10, 0);
        org.junit.Assert.assertTrue("'" + long3 + "' != '" + (-7207201254813729732L) + "'", long3 == (-7207201254813729732L));
    }

    @Test
    public void test0289() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0289");
        java.io.OutputStream outputStream0 = null;
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream3 = new org.apache.commons.codec.binary.Base16OutputStream(outputStream0, false, false);
        // The following exception was thrown during execution in test generation
        try {
            base16OutputStream3.write((int) (short) -1);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid octet in encoded value: -1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0290() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0290");
        java.lang.String str2 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt("MD5", "1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "$apr1$1842668b$BrmPcGnFkkmpTlWyJGSdY/" + "'", str2, "$apr1$1842668b$BrmPcGnFkkmpTlWyJGSdY/");
    }

    @Test
    public void test0291() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0291");
        java.lang.String str0 = org.apache.commons.codec.CharEncoding.ISO_8859_1;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "ISO-8859-1" + "'", str0, "ISO-8859-1");
    }

    @Test
    public void test0292() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0292");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray8, false);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, byteArray8);
        java.lang.String str13 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray8);
        java.lang.String str14 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray8);
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0A01640101" + "'", str11, "0A01640101");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str12, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "CgFkAQE" + "'", str13, "CgFkAQE");
// flaky:         org.junit.Assert.assertEquals("'" + str14 + "' != '" + "kBAwnYFpJm7aQ" + "'", str14, "kBAwnYFpJm7aQ");
    }

    @Test
    public void test0293() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0293");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        base64InputStream5.close();
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha3_384((java.io.InputStream) base64InputStream5);
            org.junit.Assert.fail("Expected exception of type java.io.IOException; message: Stream closed");
        } catch (java.io.IOException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    public void test0294() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0294");
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme0 = null;
        org.apache.commons.codec.language.bm.Rule.Phoneme phoneme1 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Rule.Phoneme phoneme2 = new org.apache.commons.codec.language.bm.Rule.Phoneme(phoneme0, phoneme1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0295() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0295");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16("");
        byte[] byteArray3 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray4 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray1, byteArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
    }

    @Test
    public void test0296() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0296");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream5 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.digest.XXHash32 xXHash32_8 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet9 = null;
        byte[] byteArray11 = new byte[] { (byte) 100 };
        byte[] byteArray12 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet9, byteArray11);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray12);
        byte[] byteArray14 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray12);
        xXHash32_8.update(byteArray14, (int) (byte) 10, (-690116322));
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream18 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true, 760066800, byteArray14);
        java.io.InputStream inputStream19 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream22 = new org.apache.commons.codec.binary.Base16InputStream(inputStream19, true, true);
        org.apache.commons.codec.CodecPolicy codecPolicy25 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream26 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base16InputStream22, false, false, codecPolicy25);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str27 = org.apache.commons.codec.digest.HmacUtils.hmacSha256Hex(byteArray14, (java.io.InputStream) base16InputStream26);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[100]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[100]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertTrue("'" + codecPolicy25 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy25.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0297() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0297");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(false);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_224("1nualuGt.TbmU");
        byte[] byteArray4 = quotedPrintableCodec1.decode(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = quotedPrintableCodec1.encode("$1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.", "sa|so");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: sa|so");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
    }

    @Test
    public void test0298() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0298");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        java.util.BitSet bitSet10 = null;
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        java.lang.String str19 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray16, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str20 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray16);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray16);
        java.lang.String str23 = org.apache.commons.codec.digest.Crypt.crypt(byteArray16, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec25 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet26 = null;
        byte[] byteArray28 = new byte[] { (byte) 100 };
        byte[] byteArray29 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet26, byteArray28);
        byte[] byteArray30 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray29);
        byte[] byteArray31 = uRLCodec25.encode(byteArray30);
        java.lang.String str32 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray16, byteArray30);
        byte[] byteArray33 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray16);
        byte[] byteArray34 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet10, byteArray33);
        javax.crypto.Mac mac35 = org.apache.commons.codec.digest.HmacUtils.getHmacSha1(byteArray34);
        java.lang.String str36 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex(byteArray9, byteArray34);
        char[] charArray43 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex44 = new org.apache.commons.codec.language.Soundex(charArray43);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Hex.encodeHex(byteArray34, 100, 1757052779, false, charArray43, (int) ' ');
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 100 out of bounds for length 15");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str19, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "AAAAAAA" + "'", str20, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str21, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "0Acd8L3u4hVxI" + "'", str23, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[100]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[100]");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str32 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str32, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48]");
        org.junit.Assert.assertNotNull(mac35);
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "6e57afa9a4816afe502bfa9a045f02ee2bab5660" + "'", str36, "6e57afa9a4816afe502bfa9a045f02ee2bab5660");
        org.junit.Assert.assertNotNull(charArray43);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray43), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray43), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray43), "[a, #, a]");
    }

    @Test
    public void test0299() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0299");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream5 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, false);
        org.junit.Assert.assertNotNull(outputStream0);
    }

    @Test
    public void test0300() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0300");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        java.io.InputStream inputStream7 = null;
        byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy12 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream13 = new org.apache.commons.codec.binary.Base32InputStream(inputStream7, true, (int) (byte) 0, byteArray11, codecPolicy12);
        base32InputStream13.mark((int) '-');
        // The following exception was thrown during execution in test generation
        try {
            javax.crypto.Mac mac16 = org.apache.commons.codec.digest.HmacUtils.updateHmac(mac6, (java.io.InputStream) base32InputStream13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy12 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy12.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0301() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0301");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf8("$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3.");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[36, 49, 36, 71, 77, 89, 116, 89, 82, 72, 81, 36, 82, 115, 111, 111, 109, 112, 68, 83, 53, 67, 119, 67, 85, 90, 97, 100, 107, 98, 65, 81, 51, 46]");
    }

    @Test
    public void test0302() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0302");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str6 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray2, "d7bXONth0AIyo");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: d7bXONth0AIyo");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
    }

    @Test
    public void test0303() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0303");
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
        java.nio.charset.Charset charset19 = null;
        java.nio.charset.Charset charset20 = org.apache.commons.codec.Charsets.toCharset(charset19);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str21 = quotedPrintableCodec1.encode("0A01640101", charset19);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
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
        org.junit.Assert.assertNotNull(charset20);
    }

    @Test
    public void test0304() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0304");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        java.util.Random random3 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray1, "c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a", random3);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-7, 66, -110, 8, 42, -107, -82, -73, 51, -90, 97, -114, -116, -15, 109, -48, -41, -117, 54, 3, 79, 6, -51, 54, -56, 34, 60, 91]");
    }

    @Test
    public void test0305() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0305");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray5);
        java.lang.String str9 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray7, "b29f8a352ed4b801dd66c530b4838ecdb3d500668d794fcd935a8b6f5d3a0daf38890a5bd65f5a49abfe8bbb8eedeedaf57a14baa3b3976e07182235c979aa9d");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[16, -119, -47, 37, 54, -32, -26, 90, 13, 102, -125, -62, -17, -82, -42, 127, 17, 79, -93, -47, -47, -37, -83, 106, -71, 42, 49, 70]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "b2Aup9HxaW1JY" + "'", str9, "b2Aup9HxaW1JY");
    }

    @Test
    public void test0306() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0306");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.lang.String str3 = bCodec2.getDefaultCharset();
        java.nio.charset.Charset charset5 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str6 = bCodec2.encode("\000\000\000\000\000", charset5);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "UTF-8" + "'", str3, "UTF-8");
    }

    @Test
    public void test0307() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0307");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(false);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_224("1nualuGt.TbmU");
        byte[] byteArray4 = quotedPrintableCodec1.decode(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str6 = org.apache.commons.codec.binary.StringUtils.newString(byteArray4, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalStateException; message: e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98: java.io.UnsupportedEncodingException: e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        } catch (java.lang.IllegalStateException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
    }

    @Test
    public void test0308() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0308");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = quotedPrintableCodec1.encode("");
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -3 out of bounds for length 0");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0309() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0309");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        long long1 = xXHash32_0.getValue();
        xXHash32_0.reset();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer5 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest6 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest3, byteBuffer5);
        xXHash32_0.update(byteBuffer5);
        xXHash32_0.update(1757052779);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + 46947589L + "'", long1 == 46947589L);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer5);
        org.junit.Assert.assertNotNull(messageDigest6);
        org.junit.Assert.assertEquals(messageDigest6.toString(), "MD2 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0310() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0310");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        java.lang.String str4 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray3);
        // The following exception was thrown during execution in test generation
        try {
            int int6 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray3, (int) '#');
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 0 out of bounds for length 0");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "" + "'", str4, "");
    }

    @Test
    public void test0311() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0311");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("d7bXONth0AIyo");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0312() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0312");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        org.apache.commons.codec.net.PercentCodec percentCodec15 = new org.apache.commons.codec.net.PercentCodec(byteArray5, true);
        java.lang.String str16 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
// flaky:         org.junit.Assert.assertEquals("'" + str16 + "' != '" + "$1$Zio6Xtdu$dLf9ZKkJAqnhOMStTXq2z." + "'", str16, "$1$Zio6Xtdu$dLf9ZKkJAqnhOMStTXq2z.");
    }

    @Test
    public void test0313() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0313");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer2 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteBuffer2);
        java.io.RandomAccessFile randomAccessFile4 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, randomAccessFile4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "MD2 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0314() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0314");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = uRLCodec1.encode(byteArray6);
        int int8 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str10 = org.apache.commons.codec.binary.StringUtils.newString(byteArray6, "PRSK");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalStateException; message: PRSK: java.io.UnsupportedEncodingException: PRSK");
        } catch (java.lang.IllegalStateException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertTrue("'" + int8 + "' != '" + (-690116322) + "'", int8 == (-690116322));
    }

    @Test
    public void test0315() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0315");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md2Hex("SHA-224");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "b84964d39a05eb7d1831b3cfcb20f0b6" + "'", str1, "b84964d39a05eb7d1831b3cfcb20f0b6");
    }

    @Test
    public void test0316() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0316");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
        java.lang.String str2 = uRLCodec1.getEncoding();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str5 = uRLCodec1.decode("0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea", "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: 84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3" + "'", str2, "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
    }

    @Test
    public void test0317() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0317");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_1;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray4 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet1, byteArray3);
        java.lang.String str5 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray4);
        // The following exception was thrown during execution in test generation
        try {
            javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_1 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_1));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "" + "'", str5, "");
    }

    @Test
    public void test0318() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0318");
        int int1 = org.apache.commons.codec.digest.MurmurHash3.hash32("7c7ad975a9a62c2a236991bb6b32bc68e48756ea8523b9bb1e83628af7b37776");
        org.junit.Assert.assertTrue("'" + int1 + "' != '" + 1797466354 + "'", int1 == 1797466354);
    }

    @Test
    public void test0319() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0319");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16("ALL");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-2, -1, 0, 65, 0, 76, 0, 76]");
    }

    @Test
    public void test0320() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0320");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray2);
        byte[] byteArray5 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getHmacSha1(byteArray2);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str4, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
    }

    @Test
    public void test0321() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0321");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        byte[] byteArray13 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str14 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray13);
        java.lang.String str16 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray13, false);
        byte[] byteArray17 = org.apache.commons.codec.digest.DigestUtils.sha256(byteArray13);
        // The following exception was thrown during execution in test generation
        try {
            int int20 = base64InputStream5.read(byteArray17, (-1877720325), (int) (byte) 10);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: null");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str14, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "0A01640101" + "'", str16, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[-113, 122, 46, 35, 4, 122, -60, 14, -44, 43, 101, 109, 74, -35, -124, -125, -17, 20, -70, 35, 38, -12, -60, 75, -124, 14, -124, -108, 60, 43, -6, -92]");
    }

    @Test
    public void test0322() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0322");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        java.nio.charset.Charset charset4 = qCodec3.getCharset();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str7 = qCodec3.encode("48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5", "\000h\000i\000!");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: ?h?i?!");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset4);
    }

    @Test
    public void test0323() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0323");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str2 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray0, "UTF-16LE");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0324() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0324");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str15 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray5, "$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3.");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: $1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3.");
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
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
    }

    @Test
    public void test0325() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0325");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("UTF-16BE", true);
        java.lang.String str4 = soundex2.soundex("0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "FF6U" + "'", str4, "FF6U");
    }

    @Test
    public void test0326() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0326");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray4 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        base64OutputStream1.write(byteArray4);
        byte[] byteArray8 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str9 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray8);
        java.lang.String str10 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray4, byteArray8);
        java.io.InputStream inputStream11 = null;
        byte[] byteArray15 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy16 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream17 = new org.apache.commons.codec.binary.Base32InputStream(inputStream11, true, (int) (byte) 0, byteArray15, codecPolicy16);
        base32InputStream17.mark((int) '-');
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str20 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex(byteArray8, (java.io.InputStream) base32InputStream17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "\000\ufffd" + "'", str9, "\000\ufffd");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3" + "'", str10, "a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy16 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy16.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0327() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0327");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder0.setRuleType(ruleType1);
        org.apache.commons.codec.language.bm.RuleType ruleType3 = beiderMorseEncoder0.getRuleType();
        java.lang.Class<?> wildcardClass4 = ruleType3.getClass();
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(wildcardClass4);
    }

    @Test
    public void test0328() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0328");
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str6 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray4, true);
        org.apache.commons.codec.CodecPolicy codecPolicy8 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base64 base64_9 = new org.apache.commons.codec.binary.Base64((int) (byte) 0, byteArray4, true, codecPolicy8);
        int int13 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray4, (int) 'a', 0, (-1621933077));
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "ffffff" + "'", str6, "ffffff");
        org.junit.Assert.assertTrue("'" + codecPolicy8 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy8.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertTrue("'" + int13 + "' != '" + (-2042891860) + "'", int13 == (-2042891860));
    }

    @Test
    public void test0329() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0329");
        java.lang.String str1 = org.apache.commons.codec.digest.UnixCrypt.crypt("07839f3f2ce2a945c4636a0413fb83722520cb1d91a271db0609aa223b2c0edb");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "AB//8M1zppHNA" + "'", str1, "AB//8M1zppHNA");
    }

    @Test
    public void test0330() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0330");
        org.apache.commons.codec.language.Soundex soundex1 = new org.apache.commons.codec.language.Soundex("\000\ufffd");
    }

    @Test
    public void test0331() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0331");
        org.apache.commons.codec.language.bm.NameType nameType1 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang2 = org.apache.commons.codec.language.bm.Lang.instance(nameType1);
        org.apache.commons.codec.language.bm.Languages languages3 = org.apache.commons.codec.language.bm.Languages.getInstance(nameType1);
        java.util.Set<java.lang.String> strSet4 = languages3.getLanguages();
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Lang lang5 = org.apache.commons.codec.language.bm.Lang.loadFromResource("HmacSHA224", languages3);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Unable to resolve required resource: HmacSHA224");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType1 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType1.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang2);
        org.junit.Assert.assertNotNull(languages3);
        org.junit.Assert.assertNotNull(strSet4);
    }

    @Test
    public void test0332() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0332");
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
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str20 = uRLCodec1.decode("6IiiRyxmjcARw");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: hi!");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0333() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0333");
        org.apache.commons.codec.language.DoubleMetaphone doubleMetaphone0 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.DoubleMetaphone.DoubleMetaphoneResult doubleMetaphoneResult2 = doubleMetaphone0.new DoubleMetaphoneResult((int) '-');
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: reflection call to org.apache.commons.codec.language.DoubleMetaphone$DoubleMetaphoneResult with null for superclass argument");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0334() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0334");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        byte[] byteArray9 = uRLCodec1.decode(byteArray5);
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray9);
        // The following exception was thrown during execution in test generation
        try {
            int int13 = org.apache.commons.codec.digest.MurmurHash2.hash32(byteArray10, (-690116322), 1757052779);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -690116323 out of bounds for length 20");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$1$01IszM00$RCfSq5aJ76j8Y/2M4IQqn." + "'", str8, "$1$01IszM00$RCfSq5aJ76j8Y/2M4IQqn.");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[41, -30, -36, -5, -79, 111, 99, -69, 2, 84, -33, 117, -123, -95, 91, -74, -5, 94, -110, 125]");
    }

    @Test
    public void test0335() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0335");
        org.apache.commons.codec.binary.BinaryCodec binaryCodec0 = new org.apache.commons.codec.binary.BinaryCodec();
        org.apache.commons.codec.digest.XXHash32 xXHash32_1 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet2 = null;
        byte[] byteArray4 = new byte[] { (byte) 100 };
        byte[] byteArray5 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet2, byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray5);
        xXHash32_1.update(byteArray7, (int) (byte) 10, (-690116322));
        byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray7);
        org.apache.commons.codec.net.PercentCodec percentCodec13 = new org.apache.commons.codec.net.PercentCodec(byteArray7, false);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj14 = binaryCodec0.decode((java.lang.Object) percentCodec13);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: argument not a byte array");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[-105, 58, 108, -60, 23, -121, 77, -3, 127, -30, -36, 64, -9, 119, 6, -49, 25, 62, -50, -58, 83, 123, -61, -47, -58, 26, -34, -5, -74, -87, -109, 72]");
    }

    @Test
    public void test0336() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0336");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream4 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream0, (org.apache.commons.codec.binary.BaseNCodec) base16_2, false);
        byte[] byteArray7 = new byte[] { (byte) 0, (byte) -1 };
        java.lang.String str8 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray7);
        long long9 = base16_2.getEncodedLength(byteArray7);
        byte[] byteArray15 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray15);
        java.lang.String str18 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray15, "99448658175a0534e08dbca1fe67b58231a53eec");
        byte[] byteArray19 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray15);
        byte[] byteArray20 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray7, byteArray19);
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[0, -1]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "\000\ufffd" + "'", str8, "\000\ufffd");
        org.junit.Assert.assertTrue("'" + long9 + "' != '" + 4L + "'", long9 == 4L);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str16, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str18, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[-67, -87, 98, 52, 15, 99, 110, 55, -23, -119, 3, -107, 57, 68, -49, -30, 45, -113, 30, -10, -75, 100, -27, -66, -92, 74, 87, 95, 37, 0, 100, -113, 53, -30, -122, -9, -90, -37, -69, 38, -27, 34, 70, 21, 26, 108, -48, 85, -19, 115, 112, 23, 58, 41, 39, -87, 104, 63, 37, 20, 56, 68, -1, -88]");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[-127, -6, 18, 92, -32, -119, -31, -3, -36, -12, -127, -60, 122, -22, -44, -109, -31, -55, 70, -73, -21, -51, 9, -126, 85, 112, 111, -25, 101, 85, -4, -43]");
    }

    @Test
    public void test0337() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0337");
        org.apache.commons.codec.EncoderException encoderException1 = new org.apache.commons.codec.EncoderException("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    }

    @Test
    public void test0338() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0338");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        byte[] byteArray2 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = digestUtils1.digestAsHex(byteArray2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0339() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0339");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base16 base16_2 = new org.apache.commons.codec.binary.Base16(true);
        org.apache.commons.codec.binary.BaseNCodecOutputStream baseNCodecOutputStream4 = new org.apache.commons.codec.binary.BaseNCodecOutputStream(outputStream0, (org.apache.commons.codec.binary.BaseNCodec) base16_2, false);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms5 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet6 = null;
        byte[] byteArray8 = new byte[] { (byte) 100 };
        byte[] byteArray9 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet6, byteArray8);
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray9);
        javax.crypto.Mac mac11 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms5, byteArray10);
        byte[] byteArray17 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray17);
        java.lang.String str20 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray17, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str21 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray17);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray17);
        java.lang.String str23 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray17);
        javax.crypto.Mac mac24 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms5, byteArray17);
        org.apache.commons.codec.binary.Base32 base32_26 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet27 = null;
        byte[] byteArray29 = new byte[] { (byte) 100 };
        byte[] byteArray30 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet27, byteArray29);
        byte[] byteArray31 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray30);
        boolean boolean33 = base32_26.isInAlphabet(byteArray31, false);
        byte[] byteArray35 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        java.lang.String str36 = base32_26.encodeAsString(byteArray35);
        org.apache.commons.codec.digest.HmacUtils hmacUtils37 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms5, byteArray35);
        java.lang.String str39 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray35, "$1$GMYtYRHQ$dG4e2hpzY6HAK2FvKlJCD.");
        // The following exception was thrown during execution in test generation
        try {
            baseNCodecOutputStream4.write(byteArray35);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid octet in encoded value: 0");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertTrue("'" + hmacAlgorithms5 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms5.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[100]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac11);
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str18, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str20, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "AAAAAAA" + "'", str21, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str22, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str23, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(mac24);
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[100]");
        org.junit.Assert.assertNotNull(byteArray30);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray30), "[100]");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean33 + "' != '" + false + "'", boolean33 == false);
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[0, 0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "ABUAA2IAEE======" + "'", str36, "ABUAA2IAEE======");
        org.junit.Assert.assertEquals("'" + str39 + "' != '" + "$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3." + "'", str39, "$1$GMYtYRHQ$RsoompDS5CwCUZadkbAQ3.");
    }

    @Test
    public void test0340() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0340");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        java.nio.ByteBuffer byteBuffer4 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("SHA-512/256");
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest2, byteBuffer4);
        // The following exception was thrown during execution in test generation
        try {
            int int9 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray5, 76, (int) '#', 0);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 76 out of bounds for length 64");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteBuffer4);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[95, 64, -81, 13, 25, -127, -108, 67, 56, -44, -88, -75, -99, -26, -30, 113, 23, 21, 27, -41, 118, 105, 115, 47, 101, 11, 38, -60, 92, 74, -64, -41, 6, 12, 32, 127, -27, 36, 65, -15, -87, -50, -127, 34, -41, -17, 116, -114, -90, -124, -31, -3, -42, -50, 73, 70, -5, 101, -75, -58, -79, 57, -126, 119]");
    }

    @Test
    public void test0341() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0341");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        base64InputStream5.close();
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha3_224((java.io.InputStream) base64InputStream5);
            org.junit.Assert.fail("Expected exception of type java.io.IOException; message: Stream closed");
        } catch (java.io.IOException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str6, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
    }

    @Test
    public void test0342() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0342");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator3 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) soundex2);
        int int4 = soundex2.getMaxLength();
        org.junit.Assert.assertTrue("'" + int4 + "' != '" + 4 + "'", int4 == 4);
    }

    @Test
    public void test0343() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0343");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha1("\000\000\000\000\000");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-95, 9, 9, -62, -51, -54, -11, -83, -73, -26, -80, -110, -92, -6, -70, 85, -117, 98, -67, -106]");
    }

    @Test
    public void test0344() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0344");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet0 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = languageSet0.getAny();
            org.junit.Assert.fail("Expected exception of type java.util.NoSuchElementException; message: Can't fetch any language from the empty language set.");
        } catch (java.util.NoSuchElementException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(languageSet0);
    }

    @Test
    public void test0345() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0345");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        qCodec3.setEncodeBlanks(true);
        java.lang.String str7 = qCodec3.encode("\000\000\000\000\000");
        java.io.OutputStream outputStream8 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream9 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream8);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream10 = new org.apache.commons.codec.binary.Base32OutputStream(outputStream8);
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        base32OutputStream10.write(byteArray16);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj19 = qCodec3.encode((java.lang.Object) base32OutputStream10);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type org.apache.commons.codec.binary.Base32OutputStream cannot be encoded using Q codec");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "=?UTF-8?Q?=00=00=00=00=00?=" + "'", str7, "=?UTF-8?Q?=00=00=00=00=00?=");
        org.junit.Assert.assertNotNull(outputStream8);
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
    }

    @Test
    public void test0346() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0346");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha256(byteArray5);
        org.apache.commons.codec.net.PercentCodec percentCodec11 = new org.apache.commons.codec.net.PercentCodec(byteArray5, false);
        java.nio.charset.Charset charset12 = org.apache.commons.codec.Charsets.UTF_16LE;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj13 = percentCodec11.decode((java.lang.Object) charset12);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type sun.nio.cs.UTF_16LE cannot be Percent decoded");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[-113, 122, 46, 35, 4, 122, -60, 14, -44, 43, 101, 109, 74, -35, -124, -125, -17, 20, -70, 35, 38, -12, -60, 75, -124, 14, -124, -108, 60, 43, -6, -92]");
        org.junit.Assert.assertNotNull(charset12);
    }

    @Test
    public void test0347() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0347");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.getDigest("$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1", messageDigest3);
        org.apache.commons.codec.digest.DigestUtils digestUtils5 = new org.apache.commons.codec.digest.DigestUtils(messageDigest3);
        java.io.File file6 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray7 = digestUtils5.digest(file6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest4);
        org.junit.Assert.assertEquals(messageDigest4.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0348() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0348");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("hi!");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: hi!");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0349() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0349");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUsAscii("SHA3-512");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[83, 72, 65, 51, 45, 53, 49, 50]");
    }

    @Test
    public void test0350() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0350");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = bCodec2.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: RFC 1522 violation: malformed encoded content");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
    }

    @Test
    public void test0351() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0351");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        base64OutputStream1.write(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "A6");
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "$apr1$A6$LH9Qf.ffx.HqGhcB8ODsl0" + "'", str10, "$apr1$A6$LH9Qf.ffx.HqGhcB8ODsl0");
    }

    @Test
    public void test0352() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0352");
        org.apache.commons.codec.language.Caverphone2 caverphone2_0 = new org.apache.commons.codec.language.Caverphone2();
        java.io.OutputStream outputStream1 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream2 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream1);
        byte[] byteArray6 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray6, true);
        base64OutputStream2.write(byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj10 = caverphone2_0.encode((java.lang.Object) base64OutputStream2);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Caverphone encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream1);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "ffffff" + "'", str8, "ffffff");
    }

    @Test
    public void test0353() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0353");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder2 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType3 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder2.setRuleType(ruleType3);
        // The following exception was thrown during execution in test generation
        try {
            java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap6 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType3, "0hODz3SrCKIQo");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: No rules found for gen, exact, 0hODz3SrCKIQo.");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
    }

    @Test
    public void test0354() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0354");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64((-8350299967407043051L));
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + 3254930474243051180L + "'", long1 == 3254930474243051180L);
    }

    @Test
    public void test0355() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0355");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        long long1 = xXHash32_0.getValue();
        xXHash32_0.reset();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer5 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest6 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest3, byteBuffer5);
        xXHash32_0.update(byteBuffer5);
        long long8 = xXHash32_0.getValue();
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + 46947589L + "'", long1 == 46947589L);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer5);
        org.junit.Assert.assertNotNull(messageDigest6);
        org.junit.Assert.assertEquals(messageDigest6.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertTrue("'" + long8 + "' != '" + 46947589L + "'", long8 == 46947589L);
    }

    @Test
    public void test0356() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0356");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str12 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0A01640101");
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray5);
        int int16 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray5, 4, (int) '#');
        // The following exception was thrown during execution in test generation
        try {
            long long18 = org.apache.commons.codec.digest.MurmurHash2.hash64(byteArray5, 104729);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 5 out of bounds for length 5");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "0Acd8L3u4hVxI" + "'", str12, "0Acd8L3u4hVxI");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c" + "'", str13, "84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        org.junit.Assert.assertTrue("'" + int16 + "' != '" + 1650246903 + "'", int16 == 1650246903);
    }

    @Test
    public void test0357() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0357");
        boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64("0Ac7cg1i0oNqE");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + true + "'", boolean1 == true);
    }

    @Test
    public void test0358() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0358");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            boolean boolean1 = org.apache.commons.codec.binary.Base64.isBase64(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0359() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0359");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        int int6 = base64InputStream5.available();
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_224((java.io.InputStream) base64InputStream5);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha512((java.io.InputStream) base64InputStream5);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertTrue("'" + int6 + "' != '" + 1 + "'", int6 == 1);
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[107, 78, 3, 66, 54, 103, -37, -73, 59, 110, 21, 69, 79, 14, -79, -85, -44, 89, 127, -102, 27, 7, -114, 63, 91, 90, 107, -57]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[-49, -125, -31, 53, 126, -17, -72, -67, -15, 84, 40, 80, -42, 109, -128, 7, -42, 32, -28, 5, 11, 87, 21, -36, -125, -12, -87, 33, -45, 108, -23, -50, 71, -48, -47, 60, 93, -123, -14, -80, -1, -125, 24, -46, -121, 126, -20, 47, 99, -71, 49, -67, 71, 65, 122, -127, -91, 56, 50, 122, -7, 39, -38, 62]");
    }

    @Test
    public void test0360() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0360");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("=?UTF-16LE?Q?=00=00=FD=FF?=", false);
        java.lang.String str4 = soundex2.encode("UTF-16LE");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "U=QF" + "'", str4, "U=QF");
    }

    @Test
    public void test0361() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0361");
        org.apache.commons.codec.language.Soundex soundex0 = new org.apache.commons.codec.language.Soundex();
        org.apache.commons.codec.digest.XXHash32 xXHash32_1 = new org.apache.commons.codec.digest.XXHash32();
        long long2 = xXHash32_1.getValue();
        xXHash32_1.reset();
        java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.getMd2Digest();
        java.nio.ByteBuffer byteBuffer6 = org.apache.commons.codec.binary.StringUtils.getByteBufferUtf8("8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.security.MessageDigest messageDigest7 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest4, byteBuffer6);
        xXHash32_1.update(byteBuffer6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj9 = soundex0.encode((java.lang.Object) xXHash32_1);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Soundex encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + long2 + "' != '" + 46947589L + "'", long2 == 46947589L);
        org.junit.Assert.assertNotNull(messageDigest4);
        org.junit.Assert.assertEquals(messageDigest4.toString(), "MD2 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteBuffer6);
        org.junit.Assert.assertNotNull(messageDigest7);
        org.junit.Assert.assertEquals(messageDigest7.toString(), "MD2 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0362() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0362");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha384("HXRVYJ3rI5njqeid9obvIItpLUW+F9LijCHabojojS4=");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-55, 57, 125, 32, -91, 112, 72, -115, 94, -43, -52, 6, 101, -44, -107, -27, 0, -7, 69, -7, -83, 34, -125, -107, -47, 19, 18, 49, -88, 41, 2, 66, 94, 100, 38, 6, 35, -71, -48, 10, 26, -15, -116, 68, 71, -122, -50, 58]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "00471739705a2c31cecb8fb10ee39fd74bad5cc9c783a49c72bed49fb902ccd0" + "'", str2, "00471739705a2c31cecb8fb10ee39fd74bad5cc9c783a49c72bed49fb902ccd0");
    }

    @Test
    public void test0363() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0363");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex5 = new org.apache.commons.codec.language.RefinedSoundex(charArray3);
        java.lang.String str7 = refinedSoundex5.encode("01360240043788015936020505");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = refinedSoundex5.encode("99448658175a0534e08dbca1fe67b58231a53eec");
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 4 out of bounds for length 3");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "" + "'", str7, "");
    }

    @Test
    public void test0364() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0364");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder0.setRuleType(ruleType1);
        org.apache.commons.codec.language.bm.RuleType ruleType3 = beiderMorseEncoder0.getRuleType();
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        org.apache.commons.codec.binary.Hex hex6 = new org.apache.commons.codec.binary.Hex(charset5);
        java.lang.String str7 = hex6.toString();
        java.util.BitSet bitSet8 = null;
        byte[] byteArray10 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray11 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet8, byteArray10);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray10);
        byte[] byteArray13 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray10);
        java.lang.String str14 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray10);
        byte[] byteArray15 = hex6.decode(byteArray10);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj16 = beiderMorseEncoder0.encode((java.lang.Object) byteArray15);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: BeiderMorseEncoder encode parameter is not of type String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + ruleType3 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType3.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str12, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[]");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "" + "'", str14, "");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[]");
    }

    @Test
    public void test0365() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0365");
        byte[] byteArray0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray3 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        java.io.InputStream inputStream4 = java.io.InputStream.nullInputStream();
        java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray3, inputStream4);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream6 = new org.apache.commons.codec.binary.Base64InputStream(inputStream4);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex((java.io.InputStream) base64InputStream6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = org.apache.commons.codec.digest.HmacUtils.hmacSha256Hex(byteArray0, (java.io.InputStream) base64InputStream6);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Null key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream4);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str5, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "8350e5a3e24c153df2275c9f80692773" + "'", str7, "8350e5a3e24c153df2275c9f80692773");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" + "'", str8, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    @Test
    public void test0366() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0366");
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
        byte[] byteArray23 = org.apache.commons.codec.binary.Base64.encodeBase64(byteArray11, true, false, 1757052779);
        java.lang.String str24 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray23);
        boolean boolean25 = org.apache.commons.codec.binary.Base64.isBase64(byteArray23);
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str12, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str14, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "AAAAAAA" + "'", str15, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str16, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str17, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertNotNull(obj18);
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[65, 65, 65, 65, 65, 65, 65, 61, 13, 10]");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "414141414141413d0d0a" + "'", str24, "414141414141413d0d0a");
        org.junit.Assert.assertTrue("'" + boolean25 + "' != '" + true + "'", boolean25 == true);
    }

    @Test
    public void test0367() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0367");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256("8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
        // The following exception was thrown during execution in test generation
        try {
            long[] longArray5 = org.apache.commons.codec.digest.MurmurHash3.hash128(byteArray1, 0, (-1877720325), (-1612190696));
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -1877720326 out of bounds for length 32");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-71, -85, 126, 13, -99, -78, 100, 42, -84, 71, 31, 45, -67, -103, -21, -75, 33, 116, 4, 94, 107, 11, 6, 27, 31, -74, 108, 29, -13, -54, -23, -106]");
    }

    @Test
    public void test0368() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0368");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha256("SHA-384");
        javax.crypto.Mac mac2 = org.apache.commons.codec.digest.HmacUtils.getHmacSha384(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[99, 38, -77, 37, -76, -88, -70, 75, 36, -86, -100, 50, 57, -117, -62, 68, 1, -19, 53, -38, 39, -22, -16, -23, -121, -47, 25, -17, -125, -93, -84, -21]");
        org.junit.Assert.assertNotNull(mac2);
    }

    @Test
    public void test0369() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0369");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        org.apache.commons.codec.digest.HmacUtils hmacUtils8 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream9 = null;
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy14 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream15 = new org.apache.commons.codec.binary.Base32InputStream(inputStream9, true, (int) (byte) 0, byteArray13, codecPolicy14);
        char[] charArray16 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray13);
        java.lang.String str17 = hmacUtils8.hmacHex(byteArray13);
        java.io.InputStream inputStream18 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream21 = new org.apache.commons.codec.binary.Base16InputStream(inputStream18, true, true);
        org.apache.commons.codec.CodecPolicy codecPolicy24 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream25 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base16InputStream21, false, false, codecPolicy24);
        boolean boolean26 = base16InputStream21.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str27 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray13, (java.io.InputStream) base16InputStream21);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy14 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy14.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray16);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray16), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str17, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertTrue("'" + codecPolicy24 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy24.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertTrue("'" + boolean26 + "' != '" + false + "'", boolean26 == false);
    }

    @Test
    public void test0370() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0370");
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
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str21 = uRLCodec1.encode("96978c0796ce94f7beb31576946b6bed", "ffaRlX9TmFOkk");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: ffaRlX9TmFOkk");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0371() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0371");
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
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.Blake3 blake3_19 = org.apache.commons.codec.digest.Blake3.initKeyedHash(byteArray18);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Blake3 keys must be 32 bytes");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0372() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0372");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256("8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
        // The following exception was thrown during execution in test generation
        try {
            int int5 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray1, 100, (int) (short) -1, 0);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 98 out of bounds for length 32");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-71, -85, 126, 13, -99, -78, 100, 42, -84, 71, 31, 45, -67, -103, -21, -75, 33, 116, 4, 94, 107, 11, 6, 27, 31, -74, 108, 29, -13, -54, -23, -106]");
    }

    @Test
    public void test0373() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0373");
        int int1 = org.apache.commons.codec.digest.MurmurHash3.hash32("");
        org.junit.Assert.assertTrue("'" + int1 + "' != '" + (-965378730) + "'", int1 == (-965378730));
    }

    @Test
    public void test0374() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0374");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("c6699c7aa4c4899a7838b6472b6ae7719eda306fc3de2abefd814d5909c178da");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0375() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0375");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha256Digest();
        java.nio.file.Path path1 = null;
        java.nio.file.OpenOption openOption2 = null;
        java.nio.file.OpenOption[] openOptionArray3 = new java.nio.file.OpenOption[] { openOption2 };
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, path1, openOptionArray3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-256 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(openOptionArray3);
    }

    @Test
    public void test0376() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0376");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md2Hex("ffaRlX9TmFOkk");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "b407da1ada9e730a682b465654ce978c" + "'", str1, "b407da1ada9e730a682b465654ce978c");
    }

    @Test
    public void test0377() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0377");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        byte[] byteArray9 = uRLCodec1.decode(byteArray5);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str12 = uRLCodec1.encode("c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf", "MD2");
            org.junit.Assert.fail("Expected exception of type java.io.UnsupportedEncodingException; message: MD2");
        } catch (java.io.UnsupportedEncodingException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$1$QNt8aETW$6SnPGdq/VS39VX48M6zdj0" + "'", str8, "$1$QNt8aETW$6SnPGdq/VS39VX48M6zdj0");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0]");
    }

    @Test
    public void test0378() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0378");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex("\000\000\000\000\000");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "67702a0ed25a50c46fc0a0fb46a6dfbf5333c9dc25451abdb1eeac93f1e968d5" + "'", str1, "67702a0ed25a50c46fc0a0fb46a6dfbf5333c9dc25451abdb1eeac93f1e968d5");
    }

    @Test
    public void test0379() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0379");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32(10L, 760066800);
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + (-64519185) + "'", int2 == (-64519185));
    }

    @Test
    public void test0380() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0380");
        java.lang.String str0 = org.apache.commons.codec.CharEncoding.UTF_16;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "UTF-16" + "'", str0, "UTF-16");
    }

    @Test
    public void test0381() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0381");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        org.apache.commons.codec.net.URLCodec uRLCodec3 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray7);
        byte[] byteArray10 = uRLCodec3.decode(byteArray7);
        byte[] byteArray11 = null;
        byte[] byteArray12 = uRLCodec3.decode(byteArray11);
        byte[] byteArray18 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str19 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray18);
        java.lang.String str21 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray18, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_22 = new org.apache.commons.codec.binary.Base16();
        boolean boolean24 = base16_22.isInAlphabet("AAAAAAA");
        byte[] byteArray28 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str30 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray28, true);
        java.lang.String str31 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray28);
        boolean boolean33 = base16_22.isInAlphabet(byteArray28, true);
        byte[] byteArray34 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray18, byteArray28);
        byte[] byteArray35 = uRLCodec3.encode(byteArray34);
        java.security.MessageDigest messageDigest36 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, byteArray34);
        java.io.RandomAccessFile randomAccessFile37 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray38 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, randomAccessFile37);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str9, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[100]");
        org.junit.Assert.assertNull(byteArray12);
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str19, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str21, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean24 + "' != '" + true + "'", boolean24 == true);
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "ffffff" + "'", str30, "ffffff");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str31, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean33 + "' != '" + false + "'", boolean33 == false);
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
        org.junit.Assert.assertNotNull(messageDigest36);
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA3-224 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0382() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0382");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils("$1$UYtF..0A$qlvzexZps/99jmTbfJRm11");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: $1$UYtF..0A$qlvzexZps/99jmTbfJRm11 MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0383() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0383");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex5 = new org.apache.commons.codec.language.RefinedSoundex(charArray3);
        org.apache.commons.codec.binary.Base16 base16_7 = new org.apache.commons.codec.binary.Base16(true);
        byte[] byteArray9 = org.apache.commons.codec.digest.DigestUtils.sha3_224("SHA3-256");
        java.lang.String str10 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray9);
        byte[] byteArray11 = base16_7.encode(byteArray9);
        // The following exception was thrown during execution in test generation
        try {
            int int13 = org.apache.commons.codec.binary.Hex.decodeHex(charArray3, byteArray11, 629192958);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Odd number of characters.");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
// flaky:         org.junit.Assert.assertEquals("'" + str10 + "' != '" + "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd" + "'", str10, "\ufffd\ufffd>=\013\ufffd\ufffd\ufffd\ufffd\ufffdp\r\ufffd\023\ufffd\021\ufffd\f\030\ufffd\ufffd\ufffd\ufffd");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[98, 55, 100, 54, 51, 101, 51, 100, 48, 98, 97, 52, 101, 99, 51, 48, 100, 57, 98, 50, 56, 51, 55, 48, 48, 100, 101, 56, 49, 51, 99, 100, 49, 49, 98, 54, 48, 99, 49, 56, 57, 98, 54, 55, 99, 98, 54, 57, 52, 97, 53, 56, 57, 100, 57, 50]");
    }

    @Test
    public void test0384() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0384");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha384Hex("0Acd8L3u4hVxI", "UTF-8");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "8f198685d9e52d7a95c867c39c611cfbfe2ff43aa855b443bd8be24f265b3c00c71ecd3e49ba9ce9a5d16ea9db521edb" + "'", str2, "8f198685d9e52d7a95c867c39c611cfbfe2ff43aa855b443bd8be24f265b3c00c71ecd3e49ba9ce9a5d16ea9db521edb");
    }

    @Test
    public void test0385() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0385");
        java.lang.Throwable throwable1 = null;
        org.apache.commons.codec.DecoderException decoderException2 = new org.apache.commons.codec.DecoderException(throwable1);
        org.apache.commons.codec.EncoderException encoderException3 = new org.apache.commons.codec.EncoderException();
        decoderException2.addSuppressed((java.lang.Throwable) encoderException3);
        java.lang.Throwable throwable5 = null;
        org.apache.commons.codec.DecoderException decoderException6 = new org.apache.commons.codec.DecoderException(throwable5);
        org.apache.commons.codec.EncoderException encoderException7 = new org.apache.commons.codec.EncoderException();
        decoderException6.addSuppressed((java.lang.Throwable) encoderException7);
        encoderException3.addSuppressed((java.lang.Throwable) encoderException7);
        java.lang.Throwable[] throwableArray10 = encoderException7.getSuppressed();
        org.apache.commons.codec.DecoderException decoderException11 = new org.apache.commons.codec.DecoderException((java.lang.Throwable) encoderException7);
        org.apache.commons.codec.EncoderException encoderException12 = new org.apache.commons.codec.EncoderException("49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6", (java.lang.Throwable) decoderException11);
        java.lang.String str13 = encoderException12.toString();
        org.junit.Assert.assertNotNull(throwableArray10);
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "org.apache.commons.codec.EncoderException: 49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6" + "'", str13, "org.apache.commons.codec.EncoderException: 49cc629c009ebf210ec037a1d501b7d18ef85694aff9075313e5dcdd8c010d0f0a0c65181b753ef1df7b2588062775b9b6c188c9c63e5205f4634ab4678b0df6");
    }

    @Test
    public void test0386() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0386");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("e08bf3a020bff7365364ffd559bdce7218cd9ce1c086aea324c4ef0a8ef642561afccf04698235cf68993f6416319c90", "c0c3dac62d73546bf4416981c3eff65730d490ca8245a7f5647070a126a15da6325a6f3dfd8384cf4de3e1ef35b55e3a");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm e08bf3a020bff7365364ffd559bdce7218cd9ce1c086aea324c4ef0a8ef642561afccf04698235cf68993f6416319c90 not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0387() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0387");
        char[] charArray4 = new char[] { '4', '4', ' ', 'a' };
        byte[] byteArray5 = org.apache.commons.codec.binary.BinaryCodec.fromAscii(charArray4);
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        org.junit.Assert.assertNotNull(charArray4);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray4), "44 a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray4), "44 a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray4), "[4, 4,  , a]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "" + "'", str7, "");
    }

    @Test
    public void test0388() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0388");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.apache.commons.codec.binary.Base32 base32_3 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = new byte[] { (byte) 100 };
        byte[] byteArray7 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet4, byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray7);
        boolean boolean10 = base32_3.isInAlphabet(byteArray8, false);
        int int11 = org.apache.commons.codec.digest.MurmurHash3.hash32x86(byteArray8);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray1, byteArray8);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.md2Hex(byteArray1);
        byte[] byteArray14 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-7, 66, -110, 8, 42, -107, -82, -73, 51, -90, 97, -114, -116, -15, 109, -48, -41, -117, 54, 3, 79, 6, -51, 54, -56, 34, 60, 91]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[100]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean10 + "' != '" + false + "'", boolean10 == false);
        org.junit.Assert.assertTrue("'" + int11 + "' != '" + (-690116322) + "'", int11 == (-690116322));
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "16fd67a8bb44f961f07f53972686acb3" + "'", str12, "16fd67a8bb44f961f07f53972686acb3");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "2ad36d9d51748e827af1acab7568d5e2" + "'", str13, "2ad36d9d51748e827af1acab7568d5e2");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[-123, 1, -99, 33, 46, 6, 10, -54, -88, 106, 125, 120, 39, 118, 102, 100, 69, -121, -51, 2, 109, -110, -122, 10, 100, 39, -48, 23, 88, -110, -99, 40]");
    }

    @Test
    public void test0389() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0389");
        org.apache.commons.codec.digest.PureJavaCrc32 pureJavaCrc32_0 = new org.apache.commons.codec.digest.PureJavaCrc32();
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C1 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C1.reset();
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray6 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet3, byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray5);
        pureJavaCrc32C1.update(byteArray5, (-690116322), (-1612190696));
        byte[] byteArray12 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray13 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray12);
        pureJavaCrc32C1.update(byteArray12);
        byte[] byteArray20 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray20);
        java.lang.String str23 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray20, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str24 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray20);
        byte[] byteArray25 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray12, byteArray20);
        java.util.BitSet bitSet26 = null;
        byte[] byteArray28 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray29 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet26, byteArray28);
        java.lang.String str30 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray28);
        byte[] byteArray31 = org.apache.commons.codec.digest.HmacUtils.hmacSha512(byteArray12, byteArray28);
        // The following exception was thrown during execution in test generation
        try {
            pureJavaCrc32_0.update(byteArray31, (-64519185), 64);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -64519185 out of bounds for length 64");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str7, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str21, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str23, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "AAAAAAA" + "'", str24, "AAAAAAA");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[44, 25, 81, 48, 24, -86, -111, -40, 44, -103, -115, 18, -39, 13, 31, -4, 55, -9, 40, 4, 100, -72, 12, -2, -68, 111, -122, -91, 123, -78, -42, 39, -106, -105, 87, -15, -32, 60, 52, -87, 78, 32, 122, 96, 104, 91, 55, -81]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[]");
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[]");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str30, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[-64, 47, 34, -10, 1, 61, 18, 22, 38, -97, -55, -115, 61, -75, 58, -117, -128, -125, 0, 106, 79, 53, 123, 29, -33, -113, -3, 11, 77, -35, 82, -15, 94, 30, -57, 56, 70, -51, -30, 45, 25, 88, 74, -92, -32, -76, 109, -49, -73, -74, 71, -87, -65, 110, 78, -75, -56, -89, 14, 51, -22, -30, 65, -78]");
    }

    @Test
    public void test0390() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0390");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha384Digest();
        java.io.RandomAccessFile randomAccessFile1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, randomAccessFile1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0391() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0391");
        long long1 = org.apache.commons.codec.digest.MurmurHash3.hash64(8L);
        org.junit.Assert.assertTrue("'" + long1 + "' != '" + (-2641196705367478108L) + "'", long1 == (-2641196705367478108L));
    }

    @Test
    public void test0392() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0392");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        base64OutputStream1.write(byteArray5);
        java.io.InputStream inputStream9 = null;
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy14 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream15 = new org.apache.commons.codec.binary.Base32InputStream(inputStream9, true, (int) (byte) 0, byteArray13, codecPolicy14);
        byte[] byteArray16 = org.apache.commons.codec.digest.HmacUtils.hmacMd5(byteArray5, byteArray13);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str18 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray13, "b84964d39a05eb7d1831b3cfcb20f0b6");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: b84964d39a05eb7d1831b3cfcb20f0b6");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy14 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy14.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[-16, 37, -57, -63, -51, -9, 13, 75, 7, 89, 117, -3, 104, -53, 16, -29]");
    }

    @Test
    public void test0393() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0393");
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C0 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C0.reset();
        long long2 = pureJavaCrc32C0.getValue();
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        java.lang.String str7 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray6);
        byte[] byteArray8 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            pureJavaCrc32C0.update(byteArray8, (int) (byte) 0, 1757052779);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 1 out of bounds for length 1");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + long2 + "' != '" + 0L + "'", long2 == 0L);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
// flaky:         org.junit.Assert.assertEquals("'" + str7 + "' != '" + "wUEtY64Ml2OhQ" + "'", str7, "wUEtY64Ml2OhQ");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[100]");
    }

    @Test
    public void test0394() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0394");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        java.lang.String str8 = bCodec2.getDefaultCharset();
        org.apache.commons.codec.binary.Base16 base16_9 = new org.apache.commons.codec.binary.Base16();
        boolean boolean11 = base16_9.isInAlphabet("AAAAAAA");
        byte[] byteArray15 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str17 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray15, true);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray15);
        boolean boolean20 = base16_9.isInAlphabet(byteArray15, true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj21 = bCodec2.encode((java.lang.Object) true);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type java.lang.Boolean cannot be encoded using BCodec");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "UTF-8" + "'", str8, "UTF-8");
        org.junit.Assert.assertTrue("'" + boolean11 + "' != '" + true + "'", boolean11 == true);
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "ffffff" + "'", str17, "ffffff");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str18, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean20 + "' != '" + false + "'", boolean20 == false);
    }

    @Test
    public void test0395() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0395");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray3 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray2);
        byte[] byteArray5 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        java.lang.String str6 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray2);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray2, "663b90c899fa25a111067be0c22ffc64dcf581c2");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 663b90c899fa25a111067be0c22ffc64dcf581c2");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str4, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "" + "'", str6, "");
    }

    @Test
    public void test0396() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0396");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("d2789eba1651444e3ee6cb80db8900fa");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: d2789eba1651444e3ee6cb80db8900fa");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0397() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0397");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str3 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray1, "$apr1$A6$LH9Qf.ffx.HqGhcB8ODsl0");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: $apr1$A6$LH9Qf.ffx.HqGhcB8ODsl0");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
    }

    @Test
    public void test0398() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0398");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream2);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream2);
        java.security.MessageDigest messageDigest6 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream2);
        java.io.File file7 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, file7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(messageDigest6);
        org.junit.Assert.assertEquals(messageDigest6.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0399() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0399");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        java.io.InputStream inputStream5 = java.io.InputStream.nullInputStream();
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream5);
        java.lang.String str8 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream5);
        byte[] byteArray10 = inputStream5.readNBytes((int) ' ');
        // The following exception was thrown during execution in test generation
        try {
            javax.crypto.Mac mac11 = org.apache.commons.codec.digest.HmacUtils.getHmacSha384(byteArray10);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Empty key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream3);
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str4, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str6, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str7, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str8, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[]");
    }

    @Test
    public void test0400() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0400");
        java.lang.String str2 = org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex("2ad36d9d51748e827af1acab7568d5e2", "c239987839de3feecef5bb1f8e6fe87e560fae714275023c14c043909cb43711518b509ed9e2b6ed412c9c22bc6f69a50ac2835eae30822e3a7b82ab990842bf");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "83d93cffb05d8435fffd7cd6e362a48eefb66689" + "'", str2, "83d93cffb05d8435fffd7cd6e362a48eefb66689");
    }

    @Test
    public void test0401() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0401");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.Blake3 blake3_1 = org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0402() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0402");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha512("$1$UYtF..0A$qlvzexZps/99jmTbfJRm11", "16fd67a8bb44f961f07f53972686acb3");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -107, -92, 11, 47, 35, 59, -115, 13, -76, 66, 29, 112, 107, -96, -55, -57, -1, 29, -106, -75, 58, -91, 21, -115, 62, 31, 103, 96, -87, 114, 100, -10, 46, 120, 12, -4, -109, -102, -9, 18, -37, 21, -44, 0, -69, -37, -43, -11, -3, 62, 100, 120, -33, 71, 73, -84, 67, -52, -74, 12, 107, -42, 112]");
    }

    @Test
    public void test0403() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0403");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha1("84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-41, -111, 113, 5, -74, -112, 100, -32, 28, -128, 22, -24, 77, -62, -38, 78, 65, 79, -34, 63]");
    }

    @Test
    public void test0404() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0404");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils(messageDigest0);
        java.nio.file.Path path2 = null;
        java.nio.file.OpenOption openOption3 = null;
        java.nio.file.OpenOption[] openOptionArray4 = new java.nio.file.OpenOption[] { openOption3 };
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = digestUtils1.digest(path2, openOptionArray4);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(openOptionArray4);
    }

    @Test
    public void test0405() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0405");
        org.apache.commons.codec.digest.Md5Crypt md5Crypt0 = new org.apache.commons.codec.digest.Md5Crypt();
    }

    @Test
    public void test0406() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0406");
        int int1 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) (short) -1);
        org.junit.Assert.assertTrue("'" + int1 + "' != '" + (-237789309) + "'", int1 == (-237789309));
    }

    @Test
    public void test0407() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0407");
        org.apache.commons.codec.binary.Base32 base32_1 = new org.apache.commons.codec.binary.Base32((byte) 1);
    }

    @Test
    public void test0408() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0408");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str9 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64String(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str8, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "AAAAAAA" + "'", str9, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str10, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "AAAAAAA=" + "'", str11, "AAAAAAA=");
    }

    @Test
    public void test0409() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0409");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_224Digest();
        byte[] byteArray2 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray3 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray2);
        java.io.InputStream inputStream4 = java.io.InputStream.nullInputStream();
        java.lang.String str5 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray3, inputStream4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray3);
        java.io.File file7 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, file7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/224 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream4);
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str5, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-6, -46, 89, 81, 20, -27, -60, 90, -119, 111, 52, -127, -69, 99, -25, 9, 127, -97, 16, 111, -45, 89, 28, 30, 55, -61, 15, -18]");
    }

    @Test
    public void test0410() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0410");
        org.apache.commons.codec.binary.Base64 base64_1 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy2 = base64_1.getCodecPolicy();
        boolean boolean4 = base64_1.isInAlphabet("52106e5d8bc7f95a39ebd909f7d0eb90ab9753c8c85815e28328dff4");
        org.junit.Assert.assertTrue("'" + codecPolicy2 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy2.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + true + "'", boolean4 == true);
    }

    @Test
    public void test0411() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0411");
        java.util.BitSet bitSet0 = null;
        org.apache.commons.codec.net.URLCodec uRLCodec2 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray6);
        byte[] byteArray9 = uRLCodec2.decode(byteArray6);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray11 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet0, byteArray9, true);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -2 out of bounds for length 1");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str8, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[100]");
    }

    @Test
    public void test0412() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0412");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex("\u42f9\u0892\u952a\ub7ae\ua633\u8e61\uf18c\ud06d\u8bd7\u0336\u064f\u36cd\u22c8\u5b3c");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "dba775cd82010b877fd28af00fbcb6db02bfa1f71407c48744737ad5dd19b6f1" + "'", str1, "dba775cd82010b877fd28af00fbcb6db02bfa1f71407c48744737ad5dd19b6f1");
    }

    @Test
    public void test0413() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0413");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224("SHA3-256");
        byte[] byteArray2 = org.apache.commons.codec.net.URLCodec.decodeUrl(byteArray1);
        java.lang.String str4 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray1, false);
        java.lang.String str6 = org.apache.commons.codec.digest.UnixCrypt.crypt(byteArray1, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-73, -42, 62, 61, 11, -92, -20, 48, -39, -78, -125, 112, 13, -24, 19, -51, 17, -74, 12, 24, -101, 103, -53, 105, 74, 88, -99, -110]");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "B7D63E3D0BA4EC30D9B283700DE813CD11B60C189B67CB694A589D92" + "'", str4, "B7D63E3D0BA4EC30D9B283700DE813CD11B60C189B67CB694A589D92");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "6brp3ObrccRZI" + "'", str6, "6brp3ObrccRZI");
    }

    @Test
    public void test0414() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0414");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_224Digest();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/224 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0415() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0415");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder1 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType2 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder1.setRuleType(ruleType2);
        org.apache.commons.codec.language.bm.NameType nameType4 = beiderMorseEncoder1.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType5 = beiderMorseEncoder1.getRuleType();
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet6 = org.apache.commons.codec.language.bm.Languages.NO_LANGUAGES;
        java.util.Map<java.lang.String, java.util.List<org.apache.commons.codec.language.bm.Rule>> strMap7 = org.apache.commons.codec.language.bm.Rule.getInstanceMap(nameType0, ruleType5, languageSet6);
        java.lang.String str8 = nameType0.getName();
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertTrue("'" + ruleType2 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType2.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType4 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType4.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType5 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType5.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertNotNull(languageSet6);
        org.junit.Assert.assertNotNull(strMap7);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "ash" + "'", str8, "ash");
    }

    @Test
    public void test0416() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0416");
        java.lang.String str0 = org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_256;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "SHA-256" + "'", str0, "SHA-256");
    }

    @Test
    public void test0417() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0417");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        java.lang.String str11 = org.apache.commons.codec.digest.Crypt.crypt(byteArray5, "0Acd8L3u4hVxI");
        java.util.Random random13 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str14 = org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt(byteArray5, "d2789eba1651444e3ee6cb80db8900fa", random13);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: d2789eba1651444e3ee6cb80db8900fa");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0Ac7cg1i0oNqE" + "'", str11, "0Ac7cg1i0oNqE");
    }

    @Test
    public void test0418() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0418");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256("");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_256(byteArray1);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str4 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray2, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-58, 114, -72, -47, -17, 86, -19, 40, -85, -121, -61, 98, 44, 81, 20, 6, -101, -35, 58, -41, -72, -7, 115, 116, -104, -48, -64, 30, -50, -16, -106, 122]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[32, -39, 31, 96, 101, 120, 98, 8, 87, 108, -31, 27, -25, -104, 91, 41, -2, 73, 60, -32, -6, 38, 39, 78, -25, 113, -31, -42, -88, 16, 47, 41]");
    }

    @Test
    public void test0419() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0419");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("83d93cffb05d8435fffd7cd6e362a48eefb66689", "$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm 83d93cffb05d8435fffd7cd6e362a48eefb66689 not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0420() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0420");
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
        byte[] byteArray35 = hmacUtils32.hmac(byteBuffer34);
        org.apache.commons.codec.digest.XXHash32 xXHash32_36 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet37 = null;
        byte[] byteArray39 = new byte[] { (byte) 100 };
        byte[] byteArray40 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet37, byteArray39);
        byte[] byteArray41 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray40);
        byte[] byteArray42 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray40);
        xXHash32_36.update(byteArray42, (int) (byte) 10, (-690116322));
        byte[] byteArray46 = hmacUtils32.hmac(byteArray42);
        java.util.Random random49 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str50 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray42, "ISO-8859-1", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", random49);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: ISO-8859-1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
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
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[-56, -6, 38, 92, -40, -35, -88, -80, -32, 55, -47, -60, -40, 18, -70, 57, -127, -91, 121, -38, -55, 108, 76, -109, -12, 40, 123, -90]");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[100]");
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[100]");
        org.junit.Assert.assertNotNull(byteArray41);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray41), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray42);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray42), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray46);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray46), "[39, 4, -121, 49, -15, -74, 40, -101, -30, 112, -27, -46, -54, 76, 90, -119, -70, 103, 3, -89, 123, -127, 7, -109, 39, 83, 44, 42]");
    }

    @Test
    public void test0421() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0421");
        org.apache.commons.codec.binary.Hex hex0 = new org.apache.commons.codec.binary.Hex();
        org.apache.commons.codec.language.Soundex soundex3 = new org.apache.commons.codec.language.Soundex("UTF-16BE", true);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj4 = hex0.decode((java.lang.Object) soundex3);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: class org.apache.commons.codec.language.Soundex cannot be cast to class [C (org.apache.commons.codec.language.Soundex is in unnamed module of loader 'app'; [C is in module java.base of loader 'bootstrap')");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0422() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0422");
        byte[] byteArray0 = null;
        java.lang.String str1 = org.apache.commons.codec.binary.StringUtils.newStringUtf16Le(byteArray0);
        org.junit.Assert.assertNull(str1);
    }

    @Test
    public void test0423() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0423");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.net.BCodec bCodec1 = new org.apache.commons.codec.net.BCodec("SHA-384");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.UnsupportedCharsetException; message: SHA-384");
        } catch (java.nio.charset.UnsupportedCharsetException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0424() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0424");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_256Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-256 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0425() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0425");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md5Hex("ffffff");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "eed8cdc400dfd4ec85dff70a170066b7" + "'", str1, "eed8cdc400dfd4ec85dff70a170066b7");
    }

    @Test
    public void test0426() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0426");
        org.apache.commons.codec.net.URLCodec uRLCodec1 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray5 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str7 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, true);
        java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray5);
        byte[] byteArray9 = uRLCodec1.decode(byteArray5);
        byte[] byteArray15 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str16 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray15);
        java.lang.String str18 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray15, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str19 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray15);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray15);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray15);
        java.lang.String str22 = org.apache.commons.codec.binary.StringUtils.newStringUsAscii(byteArray15);
        byte[] byteArray23 = uRLCodec1.decode(byteArray15);
        java.lang.String str24 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray15);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "ffffff" + "'", str7, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str8 + "' != '" + "$1$R3.5of0S$M7WoGc.xSqd9c0i/foPQj." + "'", str8, "$1$R3.5of0S$M7WoGc.xSqd9c0i/foPQj.");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str16 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str16, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str18, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "AAAAAAA" + "'", str19, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str20, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a" + "'", str21, "d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "\000\000\000\000\000" + "'", str22, "\000\000\000\000\000");
        org.junit.Assert.assertNotNull(byteArray23);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray23), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "65faa9d920e0e9cff43fc3f30ab02ba2e8cf6f4643b58f7c1e64583fbec8a268e677b0ec4d54406e748becb53fda210f5d4f39cf2a5014b1ca496b0805182649" + "'", str24, "65faa9d920e0e9cff43fc3f30ab02ba2e8cf6f4643b58f7c1e64583fbec8a268e677b0ec4d54406e748becb53fda210f5d4f39cf2a5014b1ca496b0805182649");
    }

    @Test
    public void test0427() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0427");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("rules");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test0428() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0428");
        int int3 = org.apache.commons.codec.digest.MurmurHash3.hash32((-7793026892456512543L), (long) (short) -1, 64);
        org.junit.Assert.assertTrue("'" + int3 + "' != '" + (-488200341) + "'", int3 == (-488200341));
    }

    @Test
    public void test0429() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0429");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        org.apache.commons.codec.net.QCodec qCodec3 = new org.apache.commons.codec.net.QCodec(charset0);
        qCodec3.setEncodeBlanks(true);
        java.lang.String str7 = qCodec3.encode("\000\000\000\000\000");
        java.nio.charset.Charset charset8 = qCodec3.getCharset();
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "=?UTF-8?Q?=00=00=00=00=00?=" + "'", str7, "=?UTF-8?Q?=00=00=00=00=00?=");
        org.junit.Assert.assertNotNull(charset8);
    }

    @Test
    public void test0430() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0430");
        org.apache.commons.codec.binary.Base64 base64_2 = new org.apache.commons.codec.binary.Base64(0);
        byte[] byteArray5 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray11 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray11);
        java.lang.String str14 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray11, false);
        java.lang.String str15 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray5, byteArray11);
        char[] charArray16 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray11);
        boolean boolean18 = base64_2.isInAlphabet(byteArray11, true);
        byte[] byteArray26 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str27 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray26);
        java.lang.String str29 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray26, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str30 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray26);
        java.io.InputStream inputStream32 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream35 = new org.apache.commons.codec.binary.Base16InputStream(inputStream32, true, true);
        org.apache.commons.codec.CodecPolicy codecPolicy38 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream39 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base16InputStream35, false, false, codecPolicy38);
        org.apache.commons.codec.binary.Base64 base64_40 = new org.apache.commons.codec.binary.Base64((int) (byte) 0, byteArray26, true, codecPolicy38);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base64 base64_41 = new org.apache.commons.codec.binary.Base64((-690116322), byteArray11, false, codecPolicy38);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineSeparator must not contain base64 characters: [??d??]");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str12, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str14 + "' != '" + "0A01640101" + "'", str14, "0A01640101");
        org.junit.Assert.assertEquals("'" + str15 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str15, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertNotNull(charArray16);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray16), "0000000100000001011001000000000100001010");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray16), "0000000100000001011001000000000100001010");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray16), "[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0]");
        org.junit.Assert.assertTrue("'" + boolean18 + "' != '" + false + "'", boolean18 == false);
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str27, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str29, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "AAAAAAA" + "'", str30, "AAAAAAA");
        org.junit.Assert.assertTrue("'" + codecPolicy38 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy38.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0431() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0431");
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
        char[] charArray20 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray12);
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
        org.junit.Assert.assertNotNull(charArray20);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray20), "0000000000000000000000000000000000000000");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray20), "0000000000000000000000000000000000000000");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray20), "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]");
    }

    @Test
    public void test0432() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0432");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream2 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true);
        // The following exception was thrown during execution in test generation
        try {
            base16InputStream2.close();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0433() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0433");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray4);
        xXHash32_0.update(byteArray6, (int) (byte) 10, (-690116322));
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray6);
        org.apache.commons.codec.net.PercentCodec percentCodec12 = new org.apache.commons.codec.net.PercentCodec(byteArray6, false);
        org.apache.commons.codec.digest.MurmurHash3.IncrementalHash32x86 incrementalHash32x86_13 = new org.apache.commons.codec.digest.MurmurHash3.IncrementalHash32x86();
        int int14 = incrementalHash32x86_13.end();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj15 = percentCodec12.decode((java.lang.Object) int14);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type java.lang.Integer cannot be Percent decoded");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[-105, 58, 108, -60, 23, -121, 77, -3, 127, -30, -36, 64, -9, 119, 6, -49, 25, 62, -50, -58, 83, 123, -61, -47, -58, 26, -34, -5, -74, -87, -109, 72]");
        org.junit.Assert.assertTrue("'" + int14 + "' != '" + 0 + "'", int14 == 0);
    }

    @Test
    public void test0434() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0434");
        org.apache.commons.codec.language.bm.NameType nameType0 = org.apache.commons.codec.language.bm.NameType.GENERIC;
        org.apache.commons.codec.language.bm.Lang lang1 = org.apache.commons.codec.language.bm.Lang.instance(nameType0);
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet3 = lang1.guessLanguages("bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.apache.commons.codec.language.bm.Languages.LanguageSet languageSet5 = lang1.guessLanguages("400000");
        java.lang.String str7 = lang1.guessLanguage("CgFkAQE");
        java.lang.String str9 = lang1.guessLanguage("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        org.junit.Assert.assertTrue("'" + nameType0 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType0.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertNotNull(lang1);
        org.junit.Assert.assertNotNull(languageSet3);
        org.junit.Assert.assertNotNull(languageSet5);
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "any" + "'", str7, "any");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "any" + "'", str9, "any");
    }

    @Test
    public void test0435() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0435");
        java.io.InputStream inputStream0 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream3 = new org.apache.commons.codec.binary.Base16InputStream(inputStream0, true, true);
        boolean boolean4 = base16InputStream3.markSupported();
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha1((java.io.InputStream) base16InputStream3);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + boolean4 + "' != '" + false + "'", boolean4 == false);
    }

    @Test
    public void test0436() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0436");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32((long) 1, (int) (short) 1);
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + 1971526657 + "'", int2 == 1971526657);
    }

    @Test
    public void test0437() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0437");
        byte[] byteArray5 = new byte[] { (byte) 100, (byte) 10, (byte) 10, (byte) 0 };
        org.apache.commons.codec.binary.Base32 base32_6 = new org.apache.commons.codec.binary.Base32((int) (byte) 0, byteArray5);
        java.util.Random random7 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str8 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray5, random7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100, 10, 10, 0]");
    }

    @Test
    public void test0438() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0438");
        org.apache.commons.codec.language.ColognePhonetic colognePhonetic0 = new org.apache.commons.codec.language.ColognePhonetic();
        java.lang.String str2 = colognePhonetic0.encode("a59cab7fb64de2a07534170f78cb8de9905aee3d1569c3a7d5af9807eb64ccd3bd0de663c5e4d736336dd1980a1113c8b7292cdf5daef562518abb81377401f3");
        char[] charArray6 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex7 = new org.apache.commons.codec.language.Soundex(charArray6);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex8 = new org.apache.commons.codec.language.RefinedSoundex(charArray6);
        org.apache.commons.codec.language.Soundex soundex9 = new org.apache.commons.codec.language.Soundex(charArray6);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj10 = colognePhonetic0.encode((java.lang.Object) soundex9);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: This method's parameter was expected to be of the type java.lang.String. But actually it was of the type org.apache.commons.codec.language.Soundex.");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "041312381228231821282818232313" + "'", str2, "041312381228231821282818232313");
        org.junit.Assert.assertNotNull(charArray6);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray6), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray6), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray6), "[a, #, a]");
    }

    @Test
    public void test0439() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0439");
        byte[] byteArray0 = null;
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        byte[] byteArray5 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray6 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray5);
        java.io.InputStream inputStream7 = java.io.InputStream.nullInputStream();
        java.lang.String str8 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray6, inputStream7);
        java.io.InputStream inputStream9 = java.io.InputStream.nullInputStream();
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream9);
        java.lang.String str11 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream9);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray6, inputStream9);
        java.security.MessageDigest messageDigest13 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream9);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray14 = org.apache.commons.codec.digest.HmacUtils.hmacMd5(byteArray0, inputStream9);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Null key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream7);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str8, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(inputStream9);
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" + "'", str10, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" + "'", str11, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str12, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(messageDigest13);
        org.junit.Assert.assertEquals(messageDigest13.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0440() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0440");
        java.lang.String str2 = org.apache.commons.codec.digest.UnixCrypt.crypt("ABUAA2IAEE======", "663b90c899fa25a111067be0c22ffc64dcf581c2");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "66/bcRxcmsqC." + "'", str2, "66/bcRxcmsqC.");
    }

    @Test
    public void test0441() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0441");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.Charsets.UTF_16BE;
        org.apache.commons.codec.net.QCodec qCodec1 = new org.apache.commons.codec.net.QCodec(charset0);
        java.nio.charset.Charset charset2 = org.apache.commons.codec.Charsets.ISO_8859_1;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj3 = qCodec1.decode((java.lang.Object) charset2);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type sun.nio.cs.ISO_8859_1 cannot be decoded using Q codec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset2);
    }

    @Test
    public void test0442() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0442");
        org.apache.commons.codec.net.QuotedPrintableCodec quotedPrintableCodec1 = new org.apache.commons.codec.net.QuotedPrintableCodec(true);
        byte[] byteArray7 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray7);
        java.lang.String str10 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray7, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str11 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray7);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(byteArray7);
        java.lang.Object obj14 = quotedPrintableCodec1.decode((java.lang.Object) byteArray7);
        java.nio.charset.Charset charset16 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy17 = null;
        org.apache.commons.codec.net.BCodec bCodec18 = new org.apache.commons.codec.net.BCodec(charset16, codecPolicy17);
        java.nio.charset.Charset charset20 = null;
        java.nio.charset.Charset charset21 = org.apache.commons.codec.Charsets.toCharset(charset20);
        java.lang.String str22 = bCodec18.encode("SHA-224", charset21);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str23 = quotedPrintableCodec1.encode("F", charset21);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -2 out of bounds for length 1");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
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
        org.junit.Assert.assertNotNull(charset21);
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str22, "=?UTF-8?B?U0hBLTIyNA==?=");
    }

    @Test
    public void test0443() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0443");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        int int6 = base64InputStream5.available();
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_224((java.io.InputStream) base64InputStream5);
        boolean boolean8 = base64InputStream5.markSupported();
        org.apache.commons.codec.binary.Base32 base32_10 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        byte[] byteArray16 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str17 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray16);
        java.lang.String str19 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray16, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str20 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray16);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray16);
        java.lang.String str23 = org.apache.commons.codec.digest.Crypt.crypt(byteArray16, "0A01640101");
        byte[] byteArray24 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray16);
        java.lang.String str25 = base32_10.encodeToString(byteArray24);
        // The following exception was thrown during execution in test generation
        try {
            int int28 = base64InputStream5.read(byteArray24, (-1877720325), 104729);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: null");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
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
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str17, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str19, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "AAAAAAA" + "'", str20, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str21, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "0Acd8L3u4hVxI" + "'", str23, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray24);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray24), "[-67, -87, 98, 52, 15, 99, 110, 55, -23, -119, 3, -107, 57, 68, -49, -30, 45, -113, 30, -10, -75, 100, -27, -66, -92, 74, 87, 95, 37, 0, 100, -113, 53, -30, -122, -9, -90, -37, -69, 38, -27, 34, 70, 21, 26, 108, -48, 85, -19, 115, 112, 23, 58, 41, 39, -87, 104, 63, 37, 20, 56, 68, -1, -88]");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "XWUWENAPMNXDP2MJAOKTSRGP4IWY6HXWWVSOLPVEJJLV6JIAMSHTLYUG66TNXOZG4UREMFI2NTIFL3LTOALTUKJHVFUD6JIUHBCP7KA=" + "'", str25, "XWUWENAPMNXDP2MJAOKTSRGP4IWY6HXWWVSOLPVEJJLV6JIAMSHTLYUG66TNXOZG4UREMFI2NTIFL3LTOALTUKJHVFUD6JIUHBCP7KA=");
    }

    @Test
    public void test0444() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0444");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream5 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.net.URLCodec uRLCodec7 = new org.apache.commons.codec.net.URLCodec("hi!");
        byte[] byteArray11 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str13 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray11, true);
        java.lang.String str14 = org.apache.commons.codec.digest.Md5Crypt.md5Crypt(byteArray11);
        byte[] byteArray15 = uRLCodec7.decode(byteArray11);
        // The following exception was thrown during execution in test generation
        try {
            base32OutputStream5.write(byteArray15, 64, 64);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: null");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "ffffff" + "'", str13, "ffffff");
// flaky:         org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$1$jglhlopw$CIxIf71kQpflp.Trc7lMd0" + "'", str14, "$1$jglhlopw$CIxIf71kQpflp.Trc7lMd0");
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[0, 0, 0]");
    }

    @Test
    public void test0445() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0445");
        // The following exception was thrown during execution in test generation
        try {
            java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset("ABUAA2IAEE======");
            org.junit.Assert.fail("Expected exception of type java.nio.charset.IllegalCharsetNameException; message: ABUAA2IAEE======");
        } catch (java.nio.charset.IllegalCharsetNameException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0446() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0446");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream1 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream1);
        java.lang.String str4 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(inputStream1);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream1);
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str3, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str4, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }

    @Test
    public void test0447() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0447");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("8350e5a3e24c153df2275c9f80692773", "2de1e68a6f21c985a8bfdaf4667db7f0a4f3ae525211724bff735c91");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-40, 59, -72, 17, -76, -13, -120, 94, -85, 105, -55, 22, 66, -72, -94, -111, -115, 14, 82, 85, -34, 19, -65, -67, -27, 25, -40, 3, -14, -33, -39, 95]");
    }

    @Test
    public void test0448() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0448");
        org.apache.commons.codec.binary.Base16 base16_0 = new org.apache.commons.codec.binary.Base16();
        org.apache.commons.codec.binary.Base32 base32_2 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray6);
        boolean boolean9 = base32_2.isInAlphabet(byteArray7, false);
        java.lang.String str10 = org.apache.commons.codec.binary.StringUtils.newStringUtf16Be(byteArray7);
        java.lang.String str11 = base16_0.encodeAsString(byteArray7);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + false + "'", boolean9 == false);
// flaky:         org.junit.Assert.assertEquals("'" + str10 + "' != '" + "\u4668\u8976\u82cc\ud2b1\uee0c\uae8d\uc559\u4729\u1f81\u9cc5\u9ee1\u26f5\ubd24\u3b18\u5257\u7414\u413a\ueed5\u780b\u5fb1\u1090\u0387\u15be\ued1b\u4a15\ub31c\u8d96\u74fb\ufffd\u191c" + "'", str10, "\u4668\u8976\u82cc\ud2b1\uee0c\uae8d\uc559\u4729\u1f81\u9cc5\u9ee1\u26f5\ubd24\u3b18\u5257\u7414\u413a\ueed5\u780b\u5fb1\u1090\u0387\u15be\ued1b\u4a15\ub31c\u8d96\u74fb\ufffd\u191c");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "4668897682CCD2B1EE0CAE8DC55947291F819CC59EE126F5BD243B1852577414413AEED5780B5FB11090038715BEED1B00714A15B31C8D9674FBDBDF7FD4191C" + "'", str11, "4668897682CCD2B1EE0CAE8DC55947291F819CC59EE126F5BD243B1852577414413AEED5780B5FB11090038715BEED1B00714A15B31C8D9674FBDBDF7FD4191C");
    }

    @Test
    public void test0449() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0449");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        boolean boolean7 = bCodec2.isStrictDecoding();
        java.nio.charset.Charset charset8 = bCodec2.getCharset();
        java.nio.charset.Charset charset9 = bCodec2.getCharset();
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertTrue("'" + boolean7 + "' != '" + false + "'", boolean7 == false);
        org.junit.Assert.assertNotNull(charset8);
        org.junit.Assert.assertNotNull(charset9);
    }

    @Test
    public void test0450() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0450");
        java.lang.String str0 = org.apache.commons.codec.language.bm.Languages.ANY;
        org.junit.Assert.assertEquals("'" + str0 + "' != '" + "any" + "'", str0, "any");
    }

    @Test
    public void test0451() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0451");
        org.apache.commons.codec.language.Nysiis nysiis0 = new org.apache.commons.codec.language.Nysiis();
    }

    @Test
    public void test0452() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0452");
        java.nio.charset.Charset charset0 = org.apache.commons.codec.binary.Hex.DEFAULT_CHARSET;
        org.apache.commons.codec.CodecPolicy codecPolicy1 = null;
        org.apache.commons.codec.net.BCodec bCodec2 = new org.apache.commons.codec.net.BCodec(charset0, codecPolicy1);
        java.nio.charset.Charset charset4 = null;
        java.nio.charset.Charset charset5 = org.apache.commons.codec.Charsets.toCharset(charset4);
        java.lang.String str6 = bCodec2.encode("SHA-224", charset5);
        org.apache.commons.codec.digest.PureJavaCrc32C pureJavaCrc32C7 = new org.apache.commons.codec.digest.PureJavaCrc32C();
        pureJavaCrc32C7.reset();
        java.util.BitSet bitSet9 = null;
        byte[] byteArray11 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray12 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet9, byteArray11);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray11);
        pureJavaCrc32C7.update(byteArray11, (-690116322), (-1612190696));
        byte[] byteArray18 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray19 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray18);
        pureJavaCrc32C7.update(byteArray18);
        byte[] byteArray26 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str27 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray26);
        java.lang.String str29 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray26, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str30 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray26);
        byte[] byteArray31 = org.apache.commons.codec.digest.HmacUtils.hmacSha384(byteArray18, byteArray26);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj32 = bCodec2.decode((java.lang.Object) byteArray26);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type [B cannot be decoded using BCodec");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset0);
        org.junit.Assert.assertNotNull(charset5);
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "=?UTF-8?B?U0hBLTIyNA==?=" + "'", str6, "=?UTF-8?B?U0hBLTIyNA==?=");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[]");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str13, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str27, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str29, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str30 + "' != '" + "AAAAAAA" + "'", str30, "AAAAAAA");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[44, 25, 81, 48, 24, -86, -111, -40, 44, -103, -115, 18, -39, 13, 31, -4, 55, -9, 40, 4, 100, -72, 12, -2, -68, 111, -122, -91, 123, -78, -42, 39, -106, -105, 87, -15, -32, 60, 52, -87, 78, 32, 122, 96, 104, 91, 55, -81]");
    }

    @Test
    public void test0453() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0453");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream3 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream5 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1, true);
        org.apache.commons.codec.digest.XXHash32 xXHash32_8 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet9 = null;
        byte[] byteArray11 = new byte[] { (byte) 100 };
        byte[] byteArray12 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet9, byteArray11);
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray12);
        byte[] byteArray14 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray12);
        xXHash32_8.update(byteArray14, (int) (byte) 10, (-690116322));
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream18 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream1, true, 760066800, byteArray14);
        org.apache.commons.codec.binary.Base32 base32_22 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet23 = null;
        byte[] byteArray25 = new byte[] { (byte) 100 };
        byte[] byteArray26 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet23, byteArray25);
        byte[] byteArray27 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray26);
        boolean boolean29 = base32_22.isInAlphabet(byteArray27, false);
        org.apache.commons.codec.CodecPolicy codecPolicy30 = base32_22.getCodecPolicy();
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream31 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base64OutputStream1, true, true, codecPolicy30);
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream32 = new org.apache.commons.codec.binary.Base64OutputStream((java.io.OutputStream) base64OutputStream1);
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[100]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[100]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray14);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray14), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[100]");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[100]");
        org.junit.Assert.assertNotNull(byteArray27);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray27), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean29 + "' != '" + false + "'", boolean29 == false);
        org.junit.Assert.assertTrue("'" + codecPolicy30 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy30.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }

    @Test
    public void test0454() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0454");
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
        byte[] byteArray35 = hmacUtils32.hmac(byteBuffer34);
        org.apache.commons.codec.digest.XXHash32 xXHash32_36 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet37 = null;
        byte[] byteArray39 = new byte[] { (byte) 100 };
        byte[] byteArray40 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet37, byteArray39);
        byte[] byteArray41 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray40);
        byte[] byteArray42 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray40);
        xXHash32_36.update(byteArray42, (int) (byte) 10, (-690116322));
        byte[] byteArray46 = hmacUtils32.hmac(byteArray42);
        java.lang.String str47 = org.apache.commons.codec.binary.StringUtils.newStringIso8859_1(byteArray46);
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
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[-56, -6, 38, 92, -40, -35, -88, -80, -32, 55, -47, -60, -40, 18, -70, 57, -127, -91, 121, -38, -55, 108, 76, -109, -12, 40, 123, -90]");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[100]");
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[100]");
        org.junit.Assert.assertNotNull(byteArray41);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray41), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray42);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray42), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray46);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray46), "[39, 4, -121, 49, -15, -74, 40, -101, -30, 112, -27, -46, -54, 76, 90, -119, -70, 103, 3, -89, 123, -127, 7, -109, 39, 83, 44, 42]");
        org.junit.Assert.assertEquals("'" + str47 + "' != '" + "'\004\2071\361\266(\233\342p\345\322\312LZ\211\272g\003\247{\201\007\223'S,*" + "'", str47, "'\004\2071\361\266(\233\342p\345\322\312LZ\211\272g\003\247{\201\007\223'S,*");
    }

    @Test
    public void test0455() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0455");
        org.apache.commons.codec.digest.DigestUtils digestUtils0 = new org.apache.commons.codec.digest.DigestUtils();
        java.io.File file1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = digestUtils0.digest(file1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0456() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0456");
        char[] charArray3 = new char[] { 'a', '#', 'a' };
        org.apache.commons.codec.language.Soundex soundex4 = new org.apache.commons.codec.language.Soundex(charArray3);
        org.apache.commons.codec.language.RefinedSoundex refinedSoundex5 = new org.apache.commons.codec.language.RefinedSoundex(charArray3);
        java.lang.String str7 = refinedSoundex5.encode("01360240043788015936020505");
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str9 = refinedSoundex5.encode("\u42f9\u0892\u952a\ub7ae\ua633\u8e61\uf18c\ud06d\u8bd7\u0336\u064f\u36cd\u22c8\u5b3c");
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 17080 out of bounds for length 3");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charArray3);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray3), "a#a");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray3), "[a, #, a]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "" + "'", str7, "");
    }

    @Test
    public void test0457() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0457");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        org.apache.commons.codec.digest.HmacUtils hmacUtils8 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream9 = null;
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy14 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream15 = new org.apache.commons.codec.binary.Base32InputStream(inputStream9, true, (int) (byte) 0, byteArray13, codecPolicy14);
        char[] charArray16 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray13);
        java.lang.String str17 = hmacUtils8.hmacHex(byteArray13);
        java.lang.String str19 = hmacUtils8.hmacHex("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy14 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy14.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray16);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray16), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str17, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertEquals("'" + str19 + "' != '" + "dfdda15d09ab512f6f012e71da796e6d22ff94eede59f4b13bbe9064" + "'", str19, "dfdda15d09ab512f6f012e71da796e6d22ff94eede59f4b13bbe9064");
    }

    @Test
    public void test0458() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0458");
        byte[] byteArray6 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray6);
        java.lang.String str9 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray6, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str10 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray6);
        org.apache.commons.codec.binary.Base64 base64_12 = new org.apache.commons.codec.binary.Base64((int) (short) 0, byteArray6, false);
        java.lang.String str13 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(byteArray6);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str7, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str9, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "AAAAAAA" + "'", str10, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str13 + "' != '" + "67702a0ed25a50c46fc0a0fb46a6dfbf5333c9dc25451abdb1eeac93f1e968d5" + "'", str13, "67702a0ed25a50c46fc0a0fb46a6dfbf5333c9dc25451abdb1eeac93f1e968d5");
    }

    @Test
    public void test0459() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0459");
        org.apache.commons.codec.language.bm.Rule.Phoneme[] phonemeArray0 = new org.apache.commons.codec.language.bm.Rule.Phoneme[] {};
        java.util.ArrayList<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeList1 = new java.util.ArrayList<org.apache.commons.codec.language.bm.Rule.Phoneme>();
        boolean boolean2 = java.util.Collections.addAll((java.util.Collection<org.apache.commons.codec.language.bm.Rule.Phoneme>) phonemeList1, phonemeArray0);
        org.apache.commons.codec.language.bm.Rule.PhonemeList phonemeList3 = new org.apache.commons.codec.language.bm.Rule.PhonemeList((java.util.List<org.apache.commons.codec.language.bm.Rule.Phoneme>) phonemeList1);
        java.util.List<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeList4 = phonemeList3.getPhonemes();
        java.lang.Iterable<org.apache.commons.codec.language.bm.Rule.Phoneme> phonemeIterable5 = phonemeList3.getPhonemes();
        org.junit.Assert.assertNotNull(phonemeArray0);
        org.junit.Assert.assertTrue("'" + boolean2 + "' != '" + false + "'", boolean2 == false);
        org.junit.Assert.assertNotNull(phonemeList4);
        org.junit.Assert.assertNotNull(phonemeIterable5);
    }

    @Test
    public void test0460() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0460");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder0.setRuleType(ruleType1);
        org.apache.commons.codec.language.bm.NameType nameType3 = beiderMorseEncoder0.getNameType();
        org.apache.commons.codec.language.bm.RuleType ruleType4 = beiderMorseEncoder0.getRuleType();
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
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj30 = beiderMorseEncoder0.encode((java.lang.Object) byteArray28);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: BeiderMorseEncoder encode parameter is not of type String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType3 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType3.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
        org.junit.Assert.assertTrue("'" + ruleType4 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType4.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
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
    }

    @Test
    public void test0461() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0461");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.HmacUtils hmacUtils2 = new org.apache.commons.codec.digest.HmacUtils("66/bcRxcmsqC.", "CBDAFA");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: Algorithm 66/bcRxcmsqC. not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0462() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0462");
        org.apache.commons.codec.language.Soundex soundex2 = new org.apache.commons.codec.language.Soundex("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", true);
        org.apache.commons.codec.StringEncoderComparator stringEncoderComparator3 = new org.apache.commons.codec.StringEncoderComparator((org.apache.commons.codec.StringEncoder) soundex2);
        soundex2.setMaxLength((int) '#');
    }

    @Test
    public void test0463() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0463");
        byte[] byteArray2 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        java.lang.String str11 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray8, false);
        java.lang.String str12 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, byteArray8);
        org.apache.commons.codec.digest.Blake3 blake3_13 = org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction(byteArray2);
        java.util.BitSet bitSet14 = null;
        byte[] byteArray20 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray20);
        java.lang.String str23 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray20, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str24 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray20);
        java.lang.String str25 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray20);
        java.lang.String str27 = org.apache.commons.codec.digest.Crypt.crypt(byteArray20, "0A01640101");
        org.apache.commons.codec.net.URLCodec uRLCodec29 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet30 = null;
        byte[] byteArray32 = new byte[] { (byte) 100 };
        byte[] byteArray33 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet30, byteArray32);
        byte[] byteArray34 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray33);
        byte[] byteArray35 = uRLCodec29.encode(byteArray34);
        java.lang.String str36 = org.apache.commons.codec.digest.HmacUtils.hmacMd5Hex(byteArray20, byteArray34);
        byte[] byteArray37 = org.apache.commons.codec.net.QuotedPrintableCodec.decodeQuotedPrintable(byteArray20);
        byte[] byteArray38 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet14, byteArray37);
        // The following exception was thrown during execution in test generation
        try {
            blake3_13.update(byteArray37, (int) '#', (int) (short) -1);
            org.junit.Assert.fail("Expected exception of type java.lang.IndexOutOfBoundsException; message: Length must be non-negative");
        } catch (java.lang.IndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "0A01640101" + "'", str11, "0A01640101");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98" + "'", str12, "e99328fd4b731be5c58dfd1970f71befba650156cfbfb21a507db1d93bc0e24eedc1e81cf47e0bd76833b179fd1ed55b4433dec4c7ee53c687472646eb96fb98");
        org.junit.Assert.assertNotNull(blake3_13);
        org.junit.Assert.assertNotNull(byteArray20);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray20), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str21, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str23 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str23, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "AAAAAAA" + "'", str24, "AAAAAAA");
        org.junit.Assert.assertEquals("'" + str25 + "' != '" + "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950" + "'", str25, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        org.junit.Assert.assertEquals("'" + str27 + "' != '" + "0Acd8L3u4hVxI" + "'", str27, "0Acd8L3u4hVxI");
        org.junit.Assert.assertNotNull(byteArray32);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray32), "[100]");
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[100]");
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray35);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray35), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
        org.junit.Assert.assertEquals("'" + str36 + "' != '" + "d2789eba1651444e3ee6cb80db8900fa" + "'", str36, "d2789eba1651444e3ee6cb80db8900fa");
        org.junit.Assert.assertNotNull(byteArray37);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray37), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertNotNull(byteArray38);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray38), "[37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48, 37, 48, 48]");
    }

    @Test
    public void test0464() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0464");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        org.apache.commons.codec.language.bm.RuleType ruleType1 = org.apache.commons.codec.language.bm.RuleType.EXACT;
        beiderMorseEncoder0.setRuleType(ruleType1);
        org.apache.commons.codec.language.bm.NameType nameType3 = beiderMorseEncoder0.getNameType();
        beiderMorseEncoder0.setConcat(false);
        org.junit.Assert.assertTrue("'" + ruleType1 + "' != '" + org.apache.commons.codec.language.bm.RuleType.EXACT + "'", ruleType1.equals(org.apache.commons.codec.language.bm.RuleType.EXACT));
        org.junit.Assert.assertTrue("'" + nameType3 + "' != '" + org.apache.commons.codec.language.bm.NameType.GENERIC + "'", nameType3.equals(org.apache.commons.codec.language.bm.NameType.GENERIC));
    }

    @Test
    public void test0465() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0465");
        org.apache.commons.codec.binary.BinaryCodec binaryCodec0 = new org.apache.commons.codec.binary.BinaryCodec();
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.apache.commons.codec.digest.DigestUtils digestUtils2 = new org.apache.commons.codec.digest.DigestUtils(messageDigest1);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj3 = binaryCodec0.decode((java.lang.Object) messageDigest1);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: argument not a byte array");
        } catch (org.apache.commons.codec.DecoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA3-384 Message Digest from SUN, <initialized>\n");
    }

    @Test
    public void test0466() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0466");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        org.apache.commons.codec.digest.HmacUtils hmacUtils8 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms0, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream9 = null;
        byte[] byteArray13 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy14 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream15 = new org.apache.commons.codec.binary.Base32InputStream(inputStream9, true, (int) (byte) 0, byteArray13, codecPolicy14);
        char[] charArray16 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray13);
        java.lang.String str17 = hmacUtils8.hmacHex(byteArray13);
        java.security.MessageDigest messageDigest18 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream19 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest20 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest18, inputStream19);
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream19);
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(inputStream19);
        byte[] byteArray26 = org.apache.commons.codec.digest.DigestUtils.sha512("$6$zee4hKQx$0mA45X5.jHNcBnBF4WWnf3n0EPvoyZOe/8w32HLGpxK5M5lsIQ1wpDTlLLCZid.2hCKZPTuzPcaBSg/r50DAt1");
        org.apache.commons.codec.binary.Base32 base32_28 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet29 = null;
        byte[] byteArray31 = new byte[] { (byte) 100 };
        byte[] byteArray32 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet29, byteArray31);
        byte[] byteArray33 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray32);
        boolean boolean35 = base32_28.isInAlphabet(byteArray33, false);
        org.apache.commons.codec.CodecPolicy codecPolicy36 = base32_28.getCodecPolicy();
        org.apache.commons.codec.binary.Base32InputStream base32InputStream37 = new org.apache.commons.codec.binary.Base32InputStream(inputStream19, false, (-965378730), byteArray26, codecPolicy36);
        java.lang.String str38 = hmacUtils8.hmacHex((java.io.InputStream) base32InputStream37);
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy14 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy14.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray16);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray16), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray16), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str17 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str17, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertNotNull(messageDigest18);
        org.junit.Assert.assertEquals(messageDigest18.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream19);
        org.junit.Assert.assertNotNull(messageDigest20);
        org.junit.Assert.assertEquals(messageDigest20.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str21, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str22, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        org.junit.Assert.assertNotNull(byteArray26);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray26), "[-23, -79, 11, -33, -89, -101, -39, -8, -117, -105, -106, -5, -21, -106, 50, -56, 21, 18, -61, -114, 105, 80, -19, -101, 10, -56, -40, -85, 92, -106, -81, -9, -50, -69, 98, -2, -85, -107, -112, -42, -17, -116, -95, 49, -86, 28, 11, -23, -119, -50, -86, -49, 59, 89, 81, 51, -52, -123, 46, -91, -69, 38, -16, -69]");
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[100]");
        org.junit.Assert.assertNotNull(byteArray32);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray32), "[100]");
        org.junit.Assert.assertNotNull(byteArray33);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray33), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertTrue("'" + boolean35 + "' != '" + false + "'", boolean35 == false);
        org.junit.Assert.assertTrue("'" + codecPolicy36 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy36.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
        org.junit.Assert.assertEquals("'" + str38 + "' != '" + "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9" + "'", str38, "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9");
    }

    @Test
    public void test0467() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0467");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex("UTF-16");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "e0eb5e9075afc82312ac3087da9fc74f638df4d4a68460d1cef92aa6c5b9dad3abd69119903c85506b374249305e00c3" + "'", str1, "e0eb5e9075afc82312ac3087da9fc74f638df4d4a68460d1cef92aa6c5b9dad3abd69119903c85506b374249305e00c3");
    }

    @Test
    public void test0468() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0468");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha256(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0469() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0469");
        java.util.BitSet bitSet0 = null;
        byte[] byteArray3 = org.apache.commons.codec.digest.HmacUtils.hmacMd5("org.apache.commons.codec.EncoderException", "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        byte[] byteArray4 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet0, byteArray3);
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-52, -57, 74, -6, 47, 76, -27, -67, -45, 6, -86, 70, -26, -31, -14, -84]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[37, 67, 67, 37, 67, 55, 74, 37, 70, 65, 37, 50, 70, 76, 37, 69, 53, 37, 66, 68, 37, 68, 51, 37, 48, 54, 37, 65, 65, 70, 37, 69, 54, 37, 69, 49, 37, 70, 50, 37, 65, 67]");
    }

    @Test
    public void test0470() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0470");
        java.lang.String str1 = org.apache.commons.codec.digest.UnixCrypt.crypt("8f198685d9e52d7a95c867c39c611cfbfe2ff43aa855b443bd8be24f265b3c00c71ecd3e49ba9ce9a5d16ea9db521edb");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "pOCLKm.YovXnk" + "'", str1, "pOCLKm.YovXnk");
    }

    @Test
    public void test0471() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0471");
        java.lang.Throwable throwable1 = null;
        org.apache.commons.codec.DecoderException decoderException2 = new org.apache.commons.codec.DecoderException(throwable1);
        org.apache.commons.codec.EncoderException encoderException3 = new org.apache.commons.codec.EncoderException();
        decoderException2.addSuppressed((java.lang.Throwable) encoderException3);
        java.lang.Throwable throwable5 = null;
        org.apache.commons.codec.DecoderException decoderException6 = new org.apache.commons.codec.DecoderException(throwable5);
        org.apache.commons.codec.EncoderException encoderException7 = new org.apache.commons.codec.EncoderException();
        decoderException6.addSuppressed((java.lang.Throwable) encoderException7);
        encoderException3.addSuppressed((java.lang.Throwable) encoderException7);
        java.lang.Throwable[] throwableArray10 = encoderException3.getSuppressed();
        org.apache.commons.codec.EncoderException encoderException11 = new org.apache.commons.codec.EncoderException("b91ea161e2e2865bb244218708f7601930d3ed7e91330610b746229c1fe626c5", (java.lang.Throwable) encoderException3);
        org.junit.Assert.assertNotNull(throwableArray10);
    }

    @Test
    public void test0472() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0472");
        java.io.OutputStream outputStream0 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream1 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream0);
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream2 = new org.apache.commons.codec.binary.Base32OutputStream(outputStream0);
        byte[] byteArray8 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray8);
        base32OutputStream2.write(byteArray8);
        byte[] byteArray13 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.binary.Base32OutputStream base32OutputStream14 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base32OutputStream2, false, 629192958, byteArray13);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: lineLength 629192958 > 0, but lineSeparator is null");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(outputStream0);
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str9, "99448658175a0534e08dbca1fe67b58231a53eec");
    }

    @Test
    public void test0473() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0473");
        java.lang.String str1 = org.apache.commons.codec.digest.Crypt.crypt("UTF-16LE");
// flaky:         org.junit.Assert.assertEquals("'" + str1 + "' != '" + "$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30" + "'", str1, "$6$olhAUVh0$fd2xFXNNKWOX3fOQQkKu1dEDI7AbqooFENR8NKmzvt.XIdWUUedSG7/qxn3Dclg4nox0CeFSDyFw9Aey9WMN30");
    }

    @Test
    public void test0474() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0474");
        org.apache.commons.codec.EncoderException encoderException1 = new org.apache.commons.codec.EncoderException("d7bXONth0AIyo");
    }

    @Test
    public void test0475() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0475");
        // The following exception was thrown during execution in test generation
        try {
            long long3 = org.apache.commons.codec.digest.MurmurHash2.hash64("84828217db05e0f40c432335572a49b77b653fc2183733677e4c111c", (int) '-', (-1));
            org.junit.Assert.fail("Expected exception of type java.lang.StringIndexOutOfBoundsException; message: begin 45, end 44, length 56");
        } catch (java.lang.StringIndexOutOfBoundsException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0476() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0476");
        org.apache.commons.codec.digest.PureJavaCrc32 pureJavaCrc32_0 = new org.apache.commons.codec.digest.PureJavaCrc32();
        pureJavaCrc32_0.update(1);
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
        // The following exception was thrown during execution in test generation
        try {
            pureJavaCrc32_0.update(byteArray15, 1650246903, (int) (short) 1);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index 1650246903 out of bounds for length 5");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
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
    }

    @Test
    public void test0477() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0477");
        org.apache.commons.codec.digest.XXHash32 xXHash32_0 = new org.apache.commons.codec.digest.XXHash32();
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes(byteArray4);
        xXHash32_0.update(byteArray6, (int) (byte) 10, (-690116322));
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray6);
        org.apache.commons.codec.net.PercentCodec percentCodec12 = new org.apache.commons.codec.net.PercentCodec(byteArray6, false);
        org.apache.commons.codec.binary.Base32 base32_14 = new org.apache.commons.codec.binary.Base32((int) (byte) 1);
        java.util.BitSet bitSet15 = null;
        byte[] byteArray17 = new byte[] { (byte) 100 };
        byte[] byteArray18 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet15, byteArray17);
        byte[] byteArray19 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray18);
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray18);
        long long21 = base32_14.getEncodedLength(byteArray18);
        byte[] byteArray22 = percentCodec12.decode(byteArray18);
        byte[] byteArray28 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str29 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray28);
        java.lang.String str31 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray28, false);
        byte[] byteArray32 = org.apache.commons.codec.digest.Blake3.hash(byteArray28);
        java.lang.String str33 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray28);
        long long34 = org.apache.commons.codec.digest.MurmurHash3.hash64(byteArray28);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj35 = percentCodec12.encode((java.lang.Object) long34);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Objects of type java.lang.Long cannot be Percent encoded");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[48, 49, 49, 48, 48, 49, 48, 48]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[-105, 58, 108, -60, 23, -121, 77, -3, 127, -30, -36, 64, -9, 119, 6, -49, 25, 62, -50, -58, 83, 123, -61, -47, -58, 26, -34, -5, -74, -87, -109, 72]");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[100]");
        org.junit.Assert.assertNotNull(byteArray18);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray18), "[100]");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str20, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertTrue("'" + long21 + "' != '" + 8L + "'", long21 == 8L);
        org.junit.Assert.assertNotNull(byteArray22);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray22), "[100]");
        org.junit.Assert.assertNotNull(byteArray28);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray28), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str29, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str31 + "' != '" + "0A01640101" + "'", str31, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray32);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray32), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertEquals("'" + str33 + "' != '" + "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62" + "'", str33, "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
        org.junit.Assert.assertTrue("'" + long34 + "' != '" + (-7793026892456512543L) + "'", long34 == (-7793026892456512543L));
    }

    @Test
    public void test0478() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0478");
        java.security.MessageDigest messageDigest1 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream2 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest3 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest1, inputStream2);
        java.security.MessageDigest messageDigest4 = org.apache.commons.codec.digest.DigestUtils.getDigest("$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1", messageDigest3);
        org.apache.commons.codec.net.URLCodec uRLCodec6 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet7 = null;
        byte[] byteArray9 = new byte[] { (byte) 100 };
        byte[] byteArray10 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet7, byteArray9);
        byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray10);
        java.lang.String str12 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray10);
        byte[] byteArray13 = uRLCodec6.decode(byteArray10);
        byte[] byteArray14 = null;
        byte[] byteArray15 = uRLCodec6.decode(byteArray14);
        byte[] byteArray21 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str22 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray21);
        java.lang.String str24 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray21, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.apache.commons.codec.binary.Base16 base16_25 = new org.apache.commons.codec.binary.Base16();
        boolean boolean27 = base16_25.isInAlphabet("AAAAAAA");
        byte[] byteArray31 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str33 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray31, true);
        java.lang.String str34 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray31);
        boolean boolean36 = base16_25.isInAlphabet(byteArray31, true);
        byte[] byteArray37 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray21, byteArray31);
        byte[] byteArray38 = uRLCodec6.encode(byteArray37);
        byte[] byteArray39 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest3, byteArray38);
        java.nio.file.Path path40 = null;
        java.nio.file.OpenOption openOption41 = null;
        java.nio.file.OpenOption[] openOptionArray42 = new java.nio.file.OpenOption[] { openOption41 };
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest43 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest3, path40, openOptionArray42);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream2);
        org.junit.Assert.assertNotNull(messageDigest3);
        org.junit.Assert.assertEquals(messageDigest3.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(messageDigest4);
        org.junit.Assert.assertEquals(messageDigest4.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[100]");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[100]");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertEquals("'" + str12 + "' != '" + "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5" + "'", str12, "48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[100]");
        org.junit.Assert.assertNull(byteArray15);
        org.junit.Assert.assertNotNull(byteArray21);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray21), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str22 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str22, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str24 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str24, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertTrue("'" + boolean27 + "' != '" + true + "'", boolean27 == true);
        org.junit.Assert.assertNotNull(byteArray31);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray31), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str33 + "' != '" + "ffffff" + "'", str33, "ffffff");
        org.junit.Assert.assertEquals("'" + str34 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str34, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertTrue("'" + boolean36 + "' != '" + false + "'", boolean36 == false);
        org.junit.Assert.assertNotNull(byteArray37);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray37), "[29, 116, 85, 96, -99, -21, 35, -103, -29, -87, -24, -99, -10, -122, -17, 32, -117, 105, 45, 69, -66, 23, -46, -30, -116, 33, -38, 110, -120, -24, -115, 46]");
        org.junit.Assert.assertNotNull(byteArray38);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray38), "[37, 49, 68, 116, 85, 37, 54, 48, 37, 57, 68, 37, 69, 66, 37, 50, 51, 37, 57, 57, 37, 69, 51, 37, 65, 57, 37, 69, 56, 37, 57, 68, 37, 70, 54, 37, 56, 54, 37, 69, 70, 43, 37, 56, 66, 105, 45, 69, 37, 66, 69, 37, 49, 55, 37, 68, 50, 37, 69, 50, 37, 56, 67, 37, 50, 49, 37, 68, 65, 110, 37, 56, 56, 37, 69, 56, 37, 56, 68, 46]");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[89, 48, -113, 108, 117, -75, 18, 115, -46, 31, -95, -63, -99, 55, 109, 104, 50, 68, -65, -41, 63, -84, 13, 102, 29, -80, -127, -9, -97, 18, -127, -124, -100, 55, 76, -105, 24, -40, 49, 88, 5, 104, 0, -71, 81, 59, -44, 99, -61, -114, 90, 127, -32, 78, -24, -69, -6, -56, -59, 38, -65, 89, -13, -92]");
        org.junit.Assert.assertNotNull(openOptionArray42);
    }

    @Test
    public void test0479() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0479");
        byte[] byteArray5 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray5);
        java.lang.String str8 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray5, false);
        byte[] byteArray9 = org.apache.commons.codec.digest.Blake3.hash(byteArray5);
        java.lang.String str10 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray5);
        long long11 = org.apache.commons.codec.digest.MurmurHash3.hash64(byteArray5);
        javax.crypto.Mac mac12 = org.apache.commons.codec.digest.HmacUtils.getHmacSha384(byteArray5);
        boolean boolean13 = org.apache.commons.codec.binary.Base64.isArrayByteBase64(byteArray5);
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[10, 1, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str6, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "0A01640101" + "'", str8, "0A01640101");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[61, 83, -68, -68, 23, 2, 87, 22, 22, 55, 33, -82, -49, -72, -59, 12, -111, 72, -103, 70, 79, -94, 84, -99, -108, -54, -25, -116, 35, -100, 80, 104]");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62" + "'", str10, "8533a802948d8ce1ce687919d20604f3febe15bdebbbcf17f93ba065ec99e1f77ffe7e9a5bc5b384bed96d11ba7a08b17c65ed993ee794d9decdd739fdcfca62");
        org.junit.Assert.assertTrue("'" + long11 + "' != '" + (-7793026892456512543L) + "'", long11 == (-7793026892456512543L));
        org.junit.Assert.assertNotNull(mac12);
        org.junit.Assert.assertTrue("'" + boolean13 + "' != '" + false + "'", boolean13 == false);
    }

    @Test
    public void test0480() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0480");
        org.apache.commons.codec.language.Nysiis nysiis1 = new org.apache.commons.codec.language.Nysiis(true);
        java.lang.String str3 = nysiis1.encode("ffffff");
        byte[] byteArray5 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray6 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray5);
        java.io.InputStream inputStream7 = java.io.InputStream.nullInputStream();
        java.lang.String str8 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray6, inputStream7);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream9 = new org.apache.commons.codec.binary.Base64InputStream(inputStream7);
        byte[] byteArray10 = org.apache.commons.codec.digest.DigestUtils.md5(inputStream7);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj11 = nysiis1.encode((java.lang.Object) byteArray10);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: Parameter supplied to Nysiis encode is not of type java.lang.String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "F" + "'", str3, "F");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(inputStream7);
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb" + "'", str8, "bd6f809cc5d8ae032b62e695f8355ccc38149e1ea8e860b08873da4ceb3457b34addf059b2b00517c285edc79b0a24b606d631b1b8a3e1963c248b0a355845cb");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104, -20, -8, 66, 126]");
    }

    @Test
    public void test0481() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0481");
        org.apache.commons.codec.language.bm.NameType nameType2 = org.apache.commons.codec.language.bm.NameType.ASHKENAZI;
        org.apache.commons.codec.language.bm.Lang lang3 = org.apache.commons.codec.language.bm.Lang.instance(nameType2);
        org.apache.commons.codec.language.bm.Languages languages4 = org.apache.commons.codec.language.bm.Languages.getInstance(nameType2);
        org.apache.commons.codec.language.bm.Lang lang5 = null; // flaky: org.apache.commons.codec.language.bm.Lang.loadFromResource("", languages4);
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.language.bm.Lang lang6 = org.apache.commons.codec.language.bm.Lang.loadFromResource("$apr1$rules$dCQ1l15gg/wUMAOsZCrfS1", languages4);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Unable to resolve required resource: $apr1$rules$dCQ1l15gg/wUMAOsZCrfS1");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + nameType2 + "' != '" + org.apache.commons.codec.language.bm.NameType.ASHKENAZI + "'", nameType2.equals(org.apache.commons.codec.language.bm.NameType.ASHKENAZI));
        org.junit.Assert.assertNotNull(lang3);
        org.junit.Assert.assertNotNull(languages4);
// flaky:         org.junit.Assert.assertNotNull(lang5);
    }

    @Test
    public void test0482() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0482");
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
        java.lang.String str21 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex((java.io.InputStream) base64InputStream18);
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
        org.junit.Assert.assertEquals("'" + str21 + "' != '" + "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" + "'", str21, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }

    @Test
    public void test0483() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0483");
        java.nio.charset.Charset charset0 = null;
        java.nio.charset.Charset charset1 = org.apache.commons.codec.Charsets.toCharset(charset0);
        org.apache.commons.codec.binary.Hex hex2 = new org.apache.commons.codec.binary.Hex(charset1);
        java.lang.String str3 = hex2.toString();
        java.util.BitSet bitSet4 = null;
        byte[] byteArray6 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray7 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet4, byteArray6);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray6);
        byte[] byteArray9 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray6);
        java.lang.String str10 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray6);
        byte[] byteArray11 = hex2.decode(byteArray6);
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms12 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet13 = null;
        byte[] byteArray15 = new byte[] { (byte) 100 };
        byte[] byteArray16 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet13, byteArray15);
        byte[] byteArray17 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray16);
        javax.crypto.Mac mac18 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms12, byteArray17);
        org.apache.commons.codec.digest.HmacUtils hmacUtils20 = new org.apache.commons.codec.digest.HmacUtils(hmacAlgorithms12, "8e8d9847b6bd198bb1980db334659e96a1bf3dbb5c56368c6fabe6f6b561232790e3b40c1d4fb50a19c349b10bdc6950");
        java.io.InputStream inputStream21 = null;
        byte[] byteArray25 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        org.apache.commons.codec.CodecPolicy codecPolicy26 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base32InputStream base32InputStream27 = new org.apache.commons.codec.binary.Base32InputStream(inputStream21, true, (int) (byte) 0, byteArray25, codecPolicy26);
        char[] charArray28 = org.apache.commons.codec.binary.BinaryCodec.toAsciiChars(byteArray25);
        java.lang.String str29 = hmacUtils20.hmacHex(byteArray25);
        java.security.MessageDigest messageDigest30 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream31 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest32 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest30, inputStream31);
        java.lang.String str33 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream31);
        byte[] byteArray34 = org.apache.commons.codec.digest.DigestUtils.sha384(inputStream31);
        java.lang.String str35 = hmacUtils20.hmacHex(inputStream31);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj36 = hex2.encode((java.lang.Object) hmacUtils20);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: class org.apache.commons.codec.digest.HmacUtils cannot be cast to class [B (org.apache.commons.codec.digest.HmacUtils is in unnamed module of loader 'app'; [B is in module java.base of loader 'bootstrap')");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(charset1);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str8, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray9);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray9), "[]");
        org.junit.Assert.assertEquals("'" + str10 + "' != '" + "" + "'", str10, "");
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[]");
        org.junit.Assert.assertTrue("'" + hmacAlgorithms12 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms12.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray15);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray15), "[100]");
        org.junit.Assert.assertNotNull(byteArray16);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray16), "[100]");
        org.junit.Assert.assertNotNull(byteArray17);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray17), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac18);
        org.junit.Assert.assertNotNull(byteArray25);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray25), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertTrue("'" + codecPolicy26 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy26.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(charArray28);
        org.junit.Assert.assertEquals(java.lang.String.copyValueOf(charArray28), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.lang.String.valueOf(charArray28), "10110010001001110101010110111001001001101110001111010000111001010110111001111110101001010111100110100010000101000000100010000110100000110000010100011001000110100001001011110001101001111010111101011110010011000000111011011101");
        org.junit.Assert.assertEquals(java.util.Arrays.toString(charArray28), "[1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1]");
        org.junit.Assert.assertEquals("'" + str29 + "' != '" + "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9" + "'", str29, "0a6d29eb22c9644a6d6249b9176f081698d55ed3adcb124d0f5171d9");
        org.junit.Assert.assertNotNull(messageDigest30);
        org.junit.Assert.assertEquals(messageDigest30.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream31);
        org.junit.Assert.assertNotNull(messageDigest32);
        org.junit.Assert.assertEquals(messageDigest32.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str33 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str33, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray34);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray34), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertEquals("'" + str35 + "' != '" + "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9" + "'", str35, "9bdec7ace9b4db8d43579cadbd09ea608a15ed697eee96158b19ccc9");
    }

    @Test
    public void test0484() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0484");
        byte[] byteArray1 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray2 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray1);
        java.io.InputStream inputStream3 = java.io.InputStream.nullInputStream();
        java.lang.String str4 = org.apache.commons.codec.digest.HmacUtils.hmacSha512Hex(byteArray2, inputStream3);
        org.apache.commons.codec.binary.Base64InputStream base64InputStream5 = new org.apache.commons.codec.binary.Base64InputStream(inputStream3);
        java.lang.String str6 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.md2Hex((java.io.InputStream) base64InputStream5);
        byte[] byteArray8 = org.apache.commons.codec.digest.DigestUtils.sha384((java.io.InputStream) base64InputStream5);
        byte[] byteArray10 = base64InputStream5.readNBytes((int) ' ');
        java.lang.String str11 = org.apache.commons.codec.binary.StringUtils.newStringUtf16(byteArray10);
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
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "" + "'", str11, "");
    }

    @Test
    public void test0485() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0485");
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str6 = org.apache.commons.codec.binary.Hex.encodeHexString(byteArray4, true);
        org.apache.commons.codec.CodecPolicy codecPolicy8 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base64 base64_9 = new org.apache.commons.codec.binary.Base64((int) (byte) 0, byteArray4, true, codecPolicy8);
        byte[] byteArray11 = org.apache.commons.codec.binary.StringUtils.getBytesUtf16Be("hi!");
        byte[] byteArray12 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray11);
        byte[] byteArray13 = base64_9.encode(byteArray11);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str15 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray13, "01230120022455012623010202");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Invalid salt value: 01230120022455012623010202");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str6 + "' != '" + "ffffff" + "'", str6, "ffffff");
        org.junit.Assert.assertTrue("'" + codecPolicy8 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy8.equals(org.apache.commons.codec.CodecPolicy.STRICT));
        org.junit.Assert.assertNotNull(byteArray11);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray11), "[0, 104, 0, 105, 0, 33]");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[65, 71, 103, 65, 97, 81, 65, 104, 13, 10]");
        org.junit.Assert.assertNotNull(byteArray13);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray13), "[65, 71, 103, 65, 97, 81, 65, 104]");
    }

    @Test
    public void test0486() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0486");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex("4c98f32a81be34128784b1e12b12b6d0067344e3e7697e56b3132f7a0ce68b473defef83edcaf80923730064ca2318078fbb9fa3444ce5ddcda20d72d173ac1d");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "bcce83622206284126038d877e184c2a80a54c5eae29897917b64bcda570c827dd2e7d0f195a31c1018fe15da1f37d47a1affa6445ab0f7d2fc7ebc0c64e7b46" + "'", str1, "bcce83622206284126038d877e184c2a80a54c5eae29897917b64bcda570c827dd2e7d0f195a31c1018fe15da1f37d47a1affa6445ab0f7d2fc7ebc0c64e7b46");
    }

    @Test
    public void test0487() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0487");
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
        java.util.BitSet bitSet37 = null;
        byte[] byteArray39 = org.apache.commons.codec.digest.DigestUtils.sha3_224("c2e00ba4220a62726f41d382082bd4fef0d9da61a66105d3fabc8aff");
        byte[] byteArray40 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet37, byteArray39);
        java.security.MessageDigest messageDigest41 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest36, byteArray39);
        java.io.File file42 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray43 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest41, file42);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest1);
        org.junit.Assert.assertEquals(messageDigest1.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(messageDigest2);
        org.junit.Assert.assertEquals(messageDigest2.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
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
        org.junit.Assert.assertEquals(messageDigest36.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
        org.junit.Assert.assertNotNull(byteArray39);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray39), "[-35, 14, 76, 94, -81, -89, -15, 18, 26, 25, 5, -125, -122, 8, 20, -94, 121, -91, 126, 110, -27, -48, -29, 38, -71, 85, 39, -78]");
        org.junit.Assert.assertNotNull(byteArray40);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray40), "[61, 68, 68, 61, 48, 69, 76, 94, 61, 65, 70, 61, 65, 55, 61, 70, 49, 61, 49, 50, 61, 49, 65, 61, 49, 57, 61, 48, 53, 61, 56, 51, 61, 56, 54, 61, 48, 56, 61, 49, 52, 61, 65, 50, 121, 61, 65, 53, 126, 110, 61, 69, 53, 61, 68, 48, 61, 69, 51, 38, 61, 66, 57, 85, 39, 61, 66, 50]");
        org.junit.Assert.assertNotNull(messageDigest41);
        org.junit.Assert.assertEquals(messageDigest41.toString(), "SHA-384 Message Digest from SUN, <in progress>\n");
    }

    @Test
    public void test0488() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0488");
        byte[] byteArray1 = org.apache.commons.codec.binary.Base64.decodeBase64("1842668b80dfd57151a4ee0eaafd2baa3bab8f776bddf680e1c29ef392dd9d9b2c003dc5d4b6c9d0a4f1ffc7a0aed397");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-41, -50, 54, -21, -81, 27, -13, 71, 95, 119, -98, -11, -25, 86, -72, 121, -19, 30, 105, -89, -35, -39, -74, -102, -35, -74, -101, -15, -2, -5, -23, -73, 93, 127, -81, 52, 123, 87, 54, -11, -25, -9, -9, 103, 93, -11, -33, 91, -39, -51, 52, -35, -41, 57, 119, -122, -6, 115, -41, 116, 107, -121, -11, 125, -9, 59, 107, 70, -98, 119, 127, 123]");
    }

    @Test
    public void test0489() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0489");
        org.apache.commons.codec.binary.BinaryCodec binaryCodec0 = new org.apache.commons.codec.binary.BinaryCodec();
        java.nio.charset.Charset charset1 = null;
        java.nio.charset.Charset charset2 = org.apache.commons.codec.Charsets.toCharset(charset1);
        org.apache.commons.codec.binary.Hex hex3 = new org.apache.commons.codec.binary.Hex(charset2);
        java.lang.String str4 = hex3.toString();
        java.util.BitSet bitSet5 = null;
        byte[] byteArray7 = org.apache.commons.codec.binary.StringUtils.getBytesIso8859_1("");
        byte[] byteArray8 = org.apache.commons.codec.net.URLCodec.encodeUrl(bitSet5, byteArray7);
        java.lang.String str9 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray7);
        byte[] byteArray10 = org.apache.commons.codec.binary.Base64.encodeBase64Chunked(byteArray7);
        java.lang.String str11 = org.apache.commons.codec.binary.StringUtils.newStringUtf8(byteArray7);
        byte[] byteArray12 = hex3.decode(byteArray7);
        java.lang.Object obj13 = binaryCodec0.decode((java.lang.Object) byteArray12);
        java.lang.String str14 = org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt(byteArray12);
        org.junit.Assert.assertNotNull(charset2);
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[]");
        org.junit.Assert.assertEquals("'" + str9 + "' != '" + "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" + "'", str9, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        org.junit.Assert.assertNotNull(byteArray10);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray10), "[]");
        org.junit.Assert.assertEquals("'" + str11 + "' != '" + "" + "'", str11, "");
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[]");
        org.junit.Assert.assertNotNull(obj13);
// flaky:         org.junit.Assert.assertEquals("'" + str14 + "' != '" + "$6$pVCQ4ubU$JUeLTrU3BV8guH48JP2PdpLRptCket2bXIuhQBB.i4T4MpaHj2faxmT/qaUCyFfFhli/WHAOxH1IGwkSplKNq." + "'", str14, "$6$pVCQ4ubU$JUeLTrU3BV8guH48JP2PdpLRptCket2bXIuhQBB.i4T4MpaHj2faxmT/qaUCyFfFhli/WHAOxH1IGwkSplKNq.");
    }

    @Test
    public void test0490() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0490");
        org.apache.commons.codec.digest.HmacAlgorithms hmacAlgorithms0 = org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224;
        java.util.BitSet bitSet1 = null;
        byte[] byteArray3 = new byte[] { (byte) 100 };
        byte[] byteArray4 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet1, byteArray3);
        byte[] byteArray5 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray4);
        javax.crypto.Mac mac6 = org.apache.commons.codec.digest.HmacUtils.getInitializedMac(hmacAlgorithms0, byteArray5);
        byte[] byteArray12 = new byte[] { (byte) 100, (byte) 10, (byte) 10, (byte) 0 };
        org.apache.commons.codec.binary.Base32 base32_13 = new org.apache.commons.codec.binary.Base32((int) (byte) 0, byteArray12);
        javax.crypto.Mac mac14 = org.apache.commons.codec.digest.HmacUtils.updateHmac(mac6, byteArray12);
        java.security.MessageDigest messageDigest15 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        java.io.InputStream inputStream16 = java.io.InputStream.nullInputStream();
        java.security.MessageDigest messageDigest17 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest15, inputStream16);
        java.lang.String str18 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream16);
        byte[] byteArray19 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream16);
        javax.crypto.Mac mac20 = org.apache.commons.codec.digest.HmacUtils.updateHmac(mac14, inputStream16);
        org.apache.commons.codec.binary.Base32InputStream base32InputStream21 = new org.apache.commons.codec.binary.Base32InputStream(inputStream16);
        java.io.OutputStream outputStream22 = null;
        java.io.OutputStream outputStream25 = java.io.OutputStream.nullOutputStream();
        org.apache.commons.codec.binary.Base64OutputStream base64OutputStream26 = new org.apache.commons.codec.binary.Base64OutputStream(outputStream25);
        byte[] byteArray29 = org.apache.commons.codec.digest.HmacUtils.hmacSha256("d3a7234b5e7f1b8bd658026eabe4e3279063f939cfdc54a83dc4cd3c55f3530441aa886cfb962ef041537e285a3dde7a", "d7d2532589ac162c9cc0fc563c6dfe373336dc7e80c96b4c7ec66b2a5cff6107");
        base64OutputStream26.write(byteArray29);
        base64OutputStream26.write((int) '4');
        base64OutputStream26.write((-1877720325));
        org.apache.commons.codec.binary.Base32OutputStream base32OutputStream35 = new org.apache.commons.codec.binary.Base32OutputStream((java.io.OutputStream) base64OutputStream26);
        byte[] byteArray44 = new byte[] { (byte) 10, (byte) 1, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str45 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray44);
        java.lang.String str47 = org.apache.commons.codec.digest.Md5Crypt.apr1Crypt(byteArray44, "99448658175a0534e08dbca1fe67b58231a53eec");
        java.lang.String str48 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArray44);
        java.io.InputStream inputStream50 = null;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream53 = new org.apache.commons.codec.binary.Base16InputStream(inputStream50, true, true);
        org.apache.commons.codec.CodecPolicy codecPolicy56 = org.apache.commons.codec.CodecPolicy.STRICT;
        org.apache.commons.codec.binary.Base16InputStream base16InputStream57 = new org.apache.commons.codec.binary.Base16InputStream((java.io.InputStream) base16InputStream53, false, false, codecPolicy56);
        org.apache.commons.codec.binary.Base64 base64_58 = new org.apache.commons.codec.binary.Base64((int) (byte) 0, byteArray44, true, codecPolicy56);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream59 = new org.apache.commons.codec.binary.Base16OutputStream((java.io.OutputStream) base32OutputStream35, true, false, codecPolicy56);
        org.apache.commons.codec.binary.Base16OutputStream base16OutputStream60 = new org.apache.commons.codec.binary.Base16OutputStream(outputStream22, false, true, codecPolicy56);
        // The following exception was thrown during execution in test generation
        try {
            long long61 = inputStream16.transferTo(outputStream22);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertTrue("'" + hmacAlgorithms0 + "' != '" + org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224 + "'", hmacAlgorithms0.equals(org.apache.commons.codec.digest.HmacAlgorithms.HMAC_SHA_224));
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[100]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[100]");
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(mac6);
        org.junit.Assert.assertNotNull(byteArray12);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray12), "[100, 10, 10, 0]");
        org.junit.Assert.assertNotNull(mac14);
        org.junit.Assert.assertNotNull(messageDigest15);
        org.junit.Assert.assertEquals(messageDigest15.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertNotNull(inputStream16);
        org.junit.Assert.assertNotNull(messageDigest17);
        org.junit.Assert.assertEquals(messageDigest17.toString(), "SHA-512 Message Digest from SUN, <initialized>\n");
        org.junit.Assert.assertEquals("'" + str18 + "' != '" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" + "'", str18, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        org.junit.Assert.assertNotNull(byteArray19);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray19), "[12, 99, -89, 91, -124, 94, 79, 125, 1, 16, 125, -123, 46, 76, 36, -123, -59, 26, 80, -86, -86, -108, -4, 97, -103, 94, 113, -69, -18, -104, 58, 42, -61, 113, 56, 49, 38, 74, -37, 71, -5, 107, -47, -32, 88, -43, -16, 4]");
        org.junit.Assert.assertNotNull(mac20);
        org.junit.Assert.assertNotNull(outputStream25);
        org.junit.Assert.assertNotNull(byteArray29);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray29), "[-26, -89, -3, 124, 3, 69, 108, -98, 85, -45, 28, 36, -105, 120, 86, 68, 29, 69, -97, 10, -1, 43, -126, 62, 2, 83, 43, -115, 69, -83, 4, 63]");
        org.junit.Assert.assertNotNull(byteArray44);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray44), "[0, 0, 0, 0, 0]");
        org.junit.Assert.assertEquals("'" + str45 + "' != '" + "99448658175a0534e08dbca1fe67b58231a53eec" + "'", str45, "99448658175a0534e08dbca1fe67b58231a53eec");
        org.junit.Assert.assertEquals("'" + str47 + "' != '" + "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1" + "'", str47, "$apr1$99448658$NHoRW3CDu86V0JLzN7aGT1");
        org.junit.Assert.assertEquals("'" + str48 + "' != '" + "AAAAAAA" + "'", str48, "AAAAAAA");
        org.junit.Assert.assertTrue("'" + codecPolicy56 + "' != '" + org.apache.commons.codec.CodecPolicy.STRICT + "'", codecPolicy56.equals(org.apache.commons.codec.CodecPolicy.STRICT));
    }

    @Test
    public void test0491() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0491");
        byte[] byteArray0 = null;
        org.apache.commons.codec.net.URLCodec uRLCodec2 = new org.apache.commons.codec.net.URLCodec("hi!");
        java.util.BitSet bitSet3 = null;
        byte[] byteArray5 = new byte[] { (byte) 100 };
        byte[] byteArray6 = org.apache.commons.codec.net.QuotedPrintableCodec.encodeQuotedPrintable(bitSet3, byteArray5);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha3_512(byteArray6);
        byte[] byteArray8 = uRLCodec2.encode(byteArray7);
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray9 = org.apache.commons.codec.digest.HmacUtils.hmacSha256(byteArray0, byteArray7);
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: Null key");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray5);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray5), "[100]");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[100]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[70, 104, -119, 118, -126, -52, -46, -79, -18, 12, -82, -115, -59, 89, 71, 41, 31, -127, -100, -59, -98, -31, 38, -11, -67, 36, 59, 24, 82, 87, 116, 20, 65, 58, -18, -43, 120, 11, 95, -79, 16, -112, 3, -121, 21, -66, -19, 27, 0, 113, 74, 21, -77, 28, -115, -106, 116, -5, -37, -33, 127, -44, 25, 28]");
        org.junit.Assert.assertNotNull(byteArray8);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray8), "[70, 104, 37, 56, 57, 118, 37, 56, 50, 37, 67, 67, 37, 68, 50, 37, 66, 49, 37, 69, 69, 37, 48, 67, 37, 65, 69, 37, 56, 68, 37, 67, 53, 89, 71, 37, 50, 57, 37, 49, 70, 37, 56, 49, 37, 57, 67, 37, 67, 53, 37, 57, 69, 37, 69, 49, 37, 50, 54, 37, 70, 53, 37, 66, 68, 37, 50, 52, 37, 51, 66, 37, 49, 56, 82, 87, 116, 37, 49, 52, 65, 37, 51, 65, 37, 69, 69, 37, 68, 53, 120, 37, 48, 66, 95, 37, 66, 49, 37, 49, 48, 37, 57, 48, 37, 48, 51, 37, 56, 55, 37, 49, 53, 37, 66, 69, 37, 69, 68, 37, 49, 66, 37, 48, 48, 113, 74, 37, 49, 53, 37, 66, 51, 37, 49, 67, 37, 56, 68, 37, 57, 54, 116, 37, 70, 66, 37, 68, 66, 37, 68, 70, 37, 55, 70, 37, 68, 52, 37, 49, 57, 37, 49, 67]");
    }

    @Test
    public void test0492() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0492");
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
        java.lang.String str20 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(inputStream14);
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
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "da39a3ee5e6b4b0d3255bfef95601890afd80709" + "'", str20, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    public void test0493() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0493");
        org.apache.commons.codec.language.Soundex soundex0 = org.apache.commons.codec.language.Soundex.US_ENGLISH_SIMPLIFIED;
        soundex0.setMaxLength((int) (byte) 10);
        org.junit.Assert.assertNotNull(soundex0);
    }

    @Test
    public void test0494() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0494");
        org.apache.commons.codec.language.Caverphone2 caverphone2_0 = new org.apache.commons.codec.language.Caverphone2();
        java.lang.String str2 = caverphone2_0.encode("SHA3-224");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "SA11111111" + "'", str2, "SA11111111");
    }

    @Test
    public void test0495() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0495");
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
        java.lang.String str20 = quotedPrintableCodec1.decode("b91ea161e2e2865bb244218708f7601930d3ed7e91330610b746229c1fe626c5", "UTF-8");
        org.apache.commons.codec.language.bm.NameType nameType21 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType22 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine25 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType21, ruleType22, false, (int) (byte) -1);
        org.apache.commons.codec.language.bm.RuleType ruleType26 = phoneticEngine25.getRuleType();
        boolean boolean27 = phoneticEngine25.isConcat();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj28 = quotedPrintableCodec1.decode((java.lang.Object) phoneticEngine25);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.DecoderException; message: Objects of type org.apache.commons.codec.language.bm.PhoneticEngine cannot be quoted-printable decoded");
        } catch (org.apache.commons.codec.DecoderException e) {
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
        org.junit.Assert.assertEquals("'" + str20 + "' != '" + "b91ea161e2e2865bb244218708f7601930d3ed7e91330610b746229c1fe626c5" + "'", str20, "b91ea161e2e2865bb244218708f7601930d3ed7e91330610b746229c1fe626c5");
        org.junit.Assert.assertNull(ruleType26);
        org.junit.Assert.assertTrue("'" + boolean27 + "' != '" + false + "'", boolean27 == false);
    }

    @Test
    public void test0496() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0496");
        int int2 = org.apache.commons.codec.digest.MurmurHash3.hash32(100L, (-8620514229188030809L));
        org.junit.Assert.assertTrue("'" + int2 + "' != '" + 1164493051 + "'", int2 == 1164493051);
    }

    @Test
    public void test0497() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0497");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test0498() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0498");
        org.apache.commons.codec.language.bm.NameType nameType0 = null;
        org.apache.commons.codec.language.bm.RuleType ruleType1 = null;
        org.apache.commons.codec.language.bm.PhoneticEngine phoneticEngine4 = new org.apache.commons.codec.language.bm.PhoneticEngine(nameType0, ruleType1, false, (int) (byte) -1);
        int int5 = phoneticEngine4.getMaxPhonemes();
        org.apache.commons.codec.language.bm.NameType nameType6 = phoneticEngine4.getNameType();
        org.junit.Assert.assertTrue("'" + int5 + "' != '" + (-1) + "'", int5 == (-1));
        org.junit.Assert.assertNull(nameType6);
    }

    @Test
    public void test0499() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0499");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224("1nualuGt.TbmU");
        // The following exception was thrown during execution in test generation
        try {
            int int5 = org.apache.commons.codec.digest.MurmurHash3.hash32(byteArray1, (int) (byte) -1, 1, (int) (short) -1);
            org.junit.Assert.fail("Expected exception of type java.lang.ArrayIndexOutOfBoundsException; message: Index -1 out of bounds for length 28");
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-99, 119, -92, -1, -1, 63, -25, 25, 51, -53, -3, -33, 4, -30, -82, 122, -21, 58, 3, 75, -125, 53, 60, -60, -52, -107, 98, 40]");
    }

    @Test
    public void test0500() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test0500");
        org.apache.commons.codec.language.bm.BeiderMorseEncoder beiderMorseEncoder0 = new org.apache.commons.codec.language.bm.BeiderMorseEncoder();
        java.lang.String str2 = beiderMorseEncoder0.encode("d41d8cd98f00b204e9800998ecf8427e");
        java.lang.String str4 = beiderMorseEncoder0.encode("SHA3-224");
        org.apache.commons.codec.binary.Base64 base64_7 = new org.apache.commons.codec.binary.Base64((int) (byte) -1);
        org.apache.commons.codec.CodecPolicy codecPolicy8 = base64_7.getCodecPolicy();
        org.apache.commons.codec.binary.Base16 base16_9 = new org.apache.commons.codec.binary.Base16(false, codecPolicy8);
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Object obj10 = beiderMorseEncoder0.encode((java.lang.Object) false);
            org.junit.Assert.fail("Expected exception of type org.apache.commons.codec.EncoderException; message: BeiderMorseEncoder encode parameter is not of type String");
        } catch (org.apache.commons.codec.EncoderException e) {
            // Expected exception.
        }
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi" + "'", str2, "tgtfbikf|tgtfbikfi|tgtfbitsfi|tgtfbizfi|tgtfbkf|tgtfbkfi|tgtfbtsfi|tgtfbzfi|tgtfvikfi|tgtfvkfi|tstfbikfi|tstfbitsfi|tstfbkfi|tstfbtsfi|ztfbikfi|ztfbizfi|ztfbkfi|ztfbzfi");
        org.junit.Assert.assertEquals("'" + str4 + "' != '" + "sa|so" + "'", str4, "sa|so");
        org.junit.Assert.assertTrue("'" + codecPolicy8 + "' != '" + org.apache.commons.codec.CodecPolicy.LENIENT + "'", codecPolicy8.equals(org.apache.commons.codec.CodecPolicy.LENIENT));
    }
}
