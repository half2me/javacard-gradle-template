package tests;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class CryptocardClient {
    private CardChannel ch;
    private SecureRandom rand;

    private static final byte CLA = 0x00;

    private static final byte getPubKeyINS = 0x00;
    private static final byte signChallengeINS = 0x01;

    private static final byte pubKeyTypeP1 = 0x00;
    private static final byte RSAPubKeyExpP1 = 0x01;
    private static final byte RSAPubKeyModP1 = 0x02;
    private static final byte ECPubKeyWP1 = 0x03;

    private static CommandAPDU getKeyType() {
        return new CommandAPDU(CLA, getPubKeyINS, pubKeyTypeP1, 0);
    }

    private static CommandAPDU getRSAPubKeyExp() {
        return new CommandAPDU(CLA, getPubKeyINS, RSAPubKeyExpP1, 0);
    }

    private static CommandAPDU getRSAPubKeyMod() {
        return new CommandAPDU(CLA, getPubKeyINS, RSAPubKeyModP1, 0);
    }

    private static CommandAPDU getECPubKeyW() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyWP1, 0);
    }

    private static CommandAPDU signChallenge(byte[] challenge) {
        return new CommandAPDU(0, signChallengeINS, 0, 0, challenge);
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
                BigInteger exp = new BigInteger(1, this.ch.transmit(getRSAPubKeyExp()).getData());
                BigInteger mod = new BigInteger(1, this.ch.transmit(getRSAPubKeyMod()).getData());
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(new RSAPublicKeySpec(mod, exp));
            case 9:
                // EC_F2M
                byte[] res = this.ch.transmit(getECPubKeyW()).getData();
                ECPoint w =

                KeyFactory kf = KeyFactory.getInstance("ECDSA");
                return kf.generatePublic(new ECPublicKeySpec(w, params));
            default:
                throw new InvalidKeySpecException("Unknown Key type");
        }
    }

    public boolean validate(PublicKey pub) throws CardException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] challenge = new byte[127];
        rand.nextBytes(challenge);
        byte[] response = this.ch.transmit(signChallenge(challenge)).getData();
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(pub);
        verifier.update(challenge);
        return verifier.verify(response);
    }
}
