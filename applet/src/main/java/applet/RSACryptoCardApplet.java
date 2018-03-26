package applet;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class RSACryptoCardApplet extends CryptoCardApplet {

    private static final short SCRATCHPAD_SIZE = 256;

    private byte[] scratchpad = JCSystem.makeTransientByteArray(SCRATCHPAD_SIZE, JCSystem.CLEAR_ON_DESELECT);

    public RSACryptoCardApplet(byte[] buffer, short offset, byte length) {
        super(buffer, offset, length);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSACryptoCardApplet(bArray, bOffset, bLength);
    }

    @Override
    protected KeyPair newKey() {
        return new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    }

    @Override
    protected Signature newSig() {
        return Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    }

    @Override
    protected void sendPublicKey(APDU apdu, short cmd) {
        switch (cmd) {
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

    private void sendRSAPublicKeyMod(APDU apdu) {
        RSAPublicKey pk = (RSAPublicKey) kp.getPublic();
        short len = pk.getModulus(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendRSAPublicKeyExp(APDU apdu) {
        RSAPublicKey pk = (RSAPublicKey) kp.getPublic();
        short len = pk.getExponent(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    @Override
    protected void signData(APDU apdu) {
        short len = sig.sign(apdu.getBuffer(), ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC], scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
