package tests;

import applet.ECCryptoCardApplet;
import applet.RSACryptoCardApplet;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.testng.annotations.*;

import java.security.PublicKey;
import java.util.Random;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class CryptoCardAppletTest {
    private Class[] applets = new Class[]{
            RSACryptoCardApplet.class,
            ECCryptoCardApplet.class
    };

    private Simulator simulator = new Simulator();
    private AID[] aids = new AID[applets.length];
    private CryptoCardClient client = new CryptoCardClient(simulator);

    public CryptoCardAppletTest() {
        Random rand = new Random();
        for (int i = 0; i < applets.length; i++) {
            byte[] aidBytes = new byte[9];
            rand.nextBytes(aidBytes);
            AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);
            simulator.installApplet(aid, applets[i]);
            aids[i] = aid;
        }
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
    public void testPubKey() throws Exception {
        for (AID a : aids) {
            simulator.selectApplet(a);

            PublicKey key = client.getPubKey();
            PublicKey key2 = client.getPubKey();
            assert (key.equals(key2));
        }
    }

    @Test
    public void testSignature() throws Exception {
        for (AID a : aids) {
            simulator.selectApplet(a);

            PublicKey pub = client.getPubKey();
            assert (client.validate(pub));
        }
    }
}
