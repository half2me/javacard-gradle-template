package applet;

import javacard.framework.*;
import javacard.security.*;

public class MainApplet extends Applet implements ISO7816 {
    private static final short SCRATCHPAD_SIZE = 256;
    private byte[] scratchpad = JCSystem.makeTransientByteArray(SCRATCHPAD_SIZE, JCSystem.CLEAR_ON_DESELECT);

    private KeyPair kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    private Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength);
    }

    public MainApplet(byte[] buffer, short offset, byte length) {
        kp.genKeyPair();
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
        register();
    }

    public void process(APDU apdu) {
        if (this.selectingApplet()) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];
        short p1 = (short) apduBuffer[ISO7816.OFFSET_P1];
        short p2 = (short) apduBuffer[ISO7816.OFFSET_P2];

        switch (ins) {
            case 0x00:
                sendPublicKey(apdu, p1);
                return;
            case 0x01:
                signData(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    protected void sendPublicKey(APDU apdu, short cmd) {
        switch (cmd) {
            case 0x00:
                sendPublicKeyType(apdu);
                return;
            case 0x01:
                sendRSAPublicKeyExp(apdu);
                return;
            case 0x02:
                sendRSAPublicKeyMod(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    protected void sendPublicKeyType(APDU apdu) {
        PublicKey pk = kp.getPublic();
        scratchpad[0] = pk.getType();
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, (short) 1);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    protected void sendRSAPublicKeyMod(APDU apdu) {
        RSAPublicKey pk = (RSAPublicKey) kp.getPublic();
        short len = pk.getModulus(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    protected void sendRSAPublicKeyExp(APDU apdu) {
        RSAPublicKey pk = (RSAPublicKey) kp.getPublic();
        short len = pk.getExponent(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    protected void signData(APDU apdu) {
        short len = sig.sign(apdu.getBuffer(), ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC], scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
