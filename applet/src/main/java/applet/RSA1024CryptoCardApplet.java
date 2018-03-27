package applet;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class RSA1024CryptoCardApplet extends RSACryptoCardApplet {

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSA1024CryptoCardApplet(bArray, bOffset, bLength);
    }

    public RSA1024CryptoCardApplet(byte[] buffer, short offset, byte length) {
        super(buffer, offset, length);
    }

    @Override
    protected KeyPair newKey() {
        return new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
    }
}
