package tests;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class CryptocardClient {
    private CardChannel ch;
    SecureRandom rand;

    private static final byte getKeyType = 0x00;
    private static final byte getRSAPubKeyExp = 0x01;
    private static final byte getRSAPubKeyMod = 0x02;
    private static final byte signChallenge = 0x03;

    private static CommandAPDU getKeyType() {
        return new CommandAPDU(0, getKeyType, 0, 0);
    }

    private static CommandAPDU getRSAPubKeyExp() {
        return new CommandAPDU(0, getRSAPubKeyExp, 0, 0);
    }

    private static CommandAPDU getRSAPubKeyMod() {
        return new CommandAPDU(0, getRSAPubKeyMod, 0, 0);
    }

    private static CommandAPDU signChallenge(byte[] challenge) {
        return new CommandAPDU(0, signChallenge, 0, 0, challenge);
    }

    CryptocardClient(CardChannel ch) {
        this.ch = ch;
        rand = new SecureRandom();
    }

    public PublicKey getPubKey() throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte type = this.ch.transmit(getKeyType()).getData()[0];

        switch (type) {
            case 4:
                // RSA
                BigInteger exp = new BigInteger(this.ch.transmit(getRSAPubKeyExp()).getData());
                BigInteger mod = new BigInteger(this.ch.transmit(getRSAPubKeyMod()).getData());
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(new RSAPublicKeySpec(mod, exp));
            default:
                throw new InvalidKeySpecException("Unknown Key type");
        }
    }

    public boolean validate(PublicKey pub) throws CardException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] challenge = new byte[64];
        rand.nextBytes(challenge);
        byte[] response = this.ch.transmit(signChallenge(challenge)).getData();
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(pub);
        verifier.update(challenge);
        return verifier.verify(response);
    }
}
