import org.junit.Assert;
import org.junit.Test;
import com.tls.tls_sigature.*;

public class TlsSigTest {
    @Test
    public void genAndVerify() {
        try {
            //Use pemfile keys to test
            String privStr = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkTfHxPa8YusG+va8\n" +
                "1CRztNQBOEr90TBEjlQBZ5d1Y0ChRANCAAS9isP/xLib7EZ1vS5OUy+gOsYBwees\n" +
                "PMDvWiTygPAUsGZv1PHLoa0ciqsElkO1fMGwNrzOKJx1Oo194Ri+SypV\n" +
                "-----END PRIVATE KEY-----";

            //change public pem string to public string
            String pubStr = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvYrD/8S4m+xGdb0uTlMvoDrGAcHn\n" +
                "rDzA71ok8oDwFLBmb9Txy6GtHIqrBJZDtXzBsDa8ziicdTqNfeEYvksqVQ==\n" +
                "-----END PUBLIC KEY-----";

            // generate signature
            tls_sigature.GenTLSSignatureResult result = tls_sigature.GenTLSSignatureEx(1400000000, "xiaojun", privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            tls_sigature.CheckTLSSignatureResult checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000000, "xiaojun", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000000, "xiaojun2", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);


            // new interface generate signature
            result = tls_sigature.genSig(1400000000, "xiaojun", privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000000, "xiaojun", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000000, "xiaojun2", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
