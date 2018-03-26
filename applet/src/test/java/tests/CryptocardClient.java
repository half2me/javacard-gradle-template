package tests;

import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECFieldElement;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.*;

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
    private static final byte ECPubKeyAP1 = 0x04;
    private static final byte ECPubKeyBP1 = 0x05;
    private static final byte ECPubKeyGP1 = 0x06;
    private static final byte ECPubKeyKP1 = 0x07;
    private static final byte ECPubKeyRP1 = 0x08;
    private static final byte ECPubKeyFieldP1 = 0x09;

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

    private static CommandAPDU getECPubKeyA() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyAP1, 0);
    }

    private static CommandAPDU getECPubKeyB() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyBP1, 0);
    }

    private static CommandAPDU getECPubKeyG() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyGP1, 0);
    }

    private static CommandAPDU getECPubKeyK() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyKP1, 0);
    }

    private static CommandAPDU getECPubKeyR() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyRP1, 0);
    }

    private static CommandAPDU getECPubKeyField() {
        return new CommandAPDU(CLA, getPubKeyINS, ECPubKeyFieldP1, 0);
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
                return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(mod, exp));
            case 9:
                // EC_F2M
                int m = 2; // Unknown magic number...
                BigInteger F = new BigInteger(1, this.ch.transmit(getECPubKeyField()).getData());
                ECField field = new ECFieldF2m(m, F);
                return getECPubKey(field);
            case 10:
                // EC_FP
                BigInteger F = new BigInteger(1, this.ch.transmit(getECPubKeyField()).getData());
                ECField field = new ECFieldFp(F);
                return getECPubKey(field);
            default:
                throw new InvalidKeySpecException("Unknown Key type");
        }
    }

    private PublicKey getECPubKey(ECField field) throws CardException {
        BigInteger A = new BigInteger(1, this.ch.transmit(getECPubKeyA()).getData());
        BigInteger B = new BigInteger(1, this.ch.transmit(getECPubKeyB()).getData());

        BigInteger R = new BigInteger(1, this.ch.transmit(getECPubKeyR()).getData());
        int K = (int) ByteBuffer.wrap(this.ch.transmit(getECPubKeyK()).getData()).order(ByteOrder.BIG_ENDIAN).getShort();
        byte[] W = this.ch.transmit(getECPubKeyW()).getData();
        byte[] G = this.ch.transmit(getECPubKeyG()).getData();

        EllipticCurve curve = new EllipticCurve(field, A, B);

        ECPoint w = ECPointUtil.decodePoint(curve, W);
        ECPoint g = ECPointUtil.decodePoint(curve, G);
        ECParameterSpec domainParams = new ECParameterSpec(curve, g, R, K);

        return KeyFactory.getInstance("ECDSA").generatePublic(new ECPublicKeySpec(w, domainParams));
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
