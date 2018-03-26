package tests;

import applet.ECCryptoCardApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import org.testng.annotations.*;

import java.security.PublicKey;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class ECCryptoCardAppletTest {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    private CryptocardClient client;

    public ECCryptoCardAppletTest() throws Exception {
        RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(ECCryptoCardApplet.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(new byte[8]);
        CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        cardMngr.Connect(runCfg);
        client = new CryptocardClient(cardMngr.getChannel());
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {

    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
    }

    @Test
    public void testECPubKey() throws Exception {
        PublicKey key = client.getPubKey();
        PublicKey key2 = client.getPubKey();
        assert (key.equals(key2));
    }

    @Test
    public void testECSignature() throws Exception {
        PublicKey pub = client.getPubKey();
        assert (client.validate(pub));
    }
}
