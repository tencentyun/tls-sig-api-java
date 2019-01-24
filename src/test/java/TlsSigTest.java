import org.junit.Assert;
import org.junit.Test;
import com.tls.tls_sigature.*;

public class TlsSigTest {
    @Test
    public void genAndVerify() {
        try {
            //Use pemfile keys to test
            String privStr = "-----BEGIN PRIVATE KEY-----\n" +
                    "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgiBPYMVTjspLfqoq46oZd\n" +
                    "j9A0C8p7aK3Fi6/4zLugCkehRANCAATU49QhsAEVfIVJUmB6SpUC6BPaku1g/dzn\n" +
                    "0Nl7iIY7W7g2FoANWnoF51eEUb6lcZ3gzfgg8VFGTpJriwHQWf5T\n" +
                    "-----END PRIVATE KEY-----";

            //change public pem string to public string
            String pubStr = "-----BEGIN PUBLIC KEY-----\n" +
                    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1OPUIbABFXyFSVJgekqVAugT2pLtYP3c\n" +
                    "59DZe4iGO1u4NhaADVp6BedXhFG+pXGd4M34IPFRRk6Sa4sB0Fn+Uw==\n" +
                    "-----END PUBLIC KEY-----";

            // generate signature
            tls_sigature.GenTLSSignatureResult result = tls_sigature.GenTLSSignatureEx(1400000955, "xiaojun", privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            tls_sigature.CheckTLSSignatureResult checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000955, "xiaojun", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000955, "xiaojun2", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);


            // new interface generate signature
            result = tls_sigature.genSig(1400000955, "xiaojun", privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000955, "xiaojun", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = tls_sigature.CheckTLSSignatureEx(result.urlSig, 1400000955, "xiaojun2", pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
