package applet;

import javacard.framework.*;
import javacard.security.*;

public class ECCryptoCardApplet extends CryptoCardApplet {

    private static final short SCRATCHPAD_SIZE = 256;

    private byte[] scratchpad = JCSystem.makeTransientByteArray(SCRATCHPAD_SIZE, JCSystem.CLEAR_ON_DESELECT);

    public ECCryptoCardApplet(byte[] buffer, short offset, byte length) {
        super(buffer, offset, length);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ECCryptoCardApplet(bArray, bOffset, bLength);
    }

    @Override
    protected KeyPair newKey() {
        return new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
    }

    @Override
    protected Signature newSig() {
        return Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    }

    @Override
    protected void sendPublicKey(APDU apdu, short cmd) {
        switch (cmd) {
            case 0x03:
                sendECPublicKeyW(apdu);
                return;
            case 0x04:
                sendECPublicKeyA(apdu);
                return;
            case 0x05:
                sendECPublicKeyB(apdu);
                return;
            case 0x06:
                sendECPublicKeyG(apdu);
                return;
            case 0x07:
                sendECPublicKeyK(apdu);
                return;
            case 0x08:
                sendECPublicKeyR(apdu);
                return;
            case 0x09:
                sendECPublicKeyField(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void sendECPublicKeyW(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getW(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendECPublicKeyA(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getA(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendECPublicKeyB(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getB(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendECPublicKeyG(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getG(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendECPublicKeyK(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        Util.setShort(scratchpad, (short) 0, pk.getK());
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, (short) 2);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    private void sendECPublicKeyR(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getR(scratchpad, (short) 0);
        Util.arrayCopyNonAtomic(scratchpad, (short) 0, apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sendECPublicKeyField(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) kp.getPublic();
        short len = pk.getField(scratchpad, (short) 0);
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
