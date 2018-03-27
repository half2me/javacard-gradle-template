package tests;

import applet.ECCryptoCardApplet;
import applet.RSACryptoCardApplet;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.testng.annotations.*;

import java.security.PublicKey;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class CryptoCardAppletTest {
    private Simulator simulator = new Simulator();
    private byte[] rsaAIDbytes = new byte[]{1, 1, 1, 1, 1, 1, 1, 1, 1};
    private byte[] ecAIDbytes = new byte[]{1, 1, 1, 1, 1, 1, 1, 1, 2};
    private AID rsaAID = new AID(rsaAIDbytes, (short) 0, (byte) rsaAIDbytes.length);
    private AID ecAID = new AID(ecAIDbytes, (short) 0, (byte) ecAIDbytes.length);
    private CryptoCardClient client = new CryptoCardClient(simulator);

    public CryptoCardAppletTest() throws Exception {

        simulator.installApplet(rsaAID, RSACryptoCardApplet.class);
        simulator.installApplet(ecAID, ECCryptoCardApplet.class);
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
        simulator.selectApplet(ecAID);

        PublicKey key = client.getPubKey();
        PublicKey key2 = client.getPubKey();
        assert (key.equals(key2));
    }

    @Test
    public void testRSAPubKey() throws Exception {
        simulator.selectApplet(rsaAID);

        PublicKey key = client.getPubKey();
        PublicKey key2 = client.getPubKey();
        assert (key.equals(key2));
    }

    @Test
    public void testECSignature() throws Exception {
        simulator.selectApplet(ecAID);

        PublicKey pub = client.getPubKey();
        assert (client.validate(pub));
    }

    @Test
    public void testRSASignature() throws Exception {
        simulator.selectApplet(rsaAID);

        PublicKey pub = client.getPubKey();
        assert (client.validate(pub));
    }
}
