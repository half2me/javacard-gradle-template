package applet;

import javacard.framework.*;
import javacard.security.*;

public abstract class CryptoCardApplet extends Applet implements ISO7816 {
    KeyPair kp;
    Signature sig;

    CryptoCardApplet(byte[] buffer, short offset, byte length) {
        kp = newKey();
        kp.genKeyPair();
        sig = newSig();
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
        register();
    }

    protected abstract KeyPair newKey();
    protected abstract Signature newSig();
    protected abstract void sendPublicKey(APDU apdu, short p1);
    protected abstract void signData(APDU apdu);

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
                if (p1 == 0x00) {
                    sendPublicKeyType(apdu);
                } else {
                    sendPublicKey(apdu, p1);
                }
                return;
            case 0x01:
                signData(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendPublicKeyType(APDU apdu) {
        PublicKey pk = kp.getPublic();
        apdu.getBuffer()[0] = pk.getType();
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
}
