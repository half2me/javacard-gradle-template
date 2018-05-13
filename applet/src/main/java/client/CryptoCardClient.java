package client;

import com.licel.jcardsim.io.CardInterface;
import org.bouncycastle.jce.ECPointUtil;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.*;

public class CryptoCardClient {
    private CardInterface card;
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

    public CryptoCardClient(CardInterface card) {
        this.card = card;
        rand = new SecureRandom();
    }

    public PublicKey getPubKey() throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte type = transmit(getKeyType()).getData()[0];


        switch (type) {
            case 4:
                // RSA
                BigInteger exp = new BigInteger(1, transmit(getRSAPubKeyExp()).getData());
                BigInteger mod = new BigInteger(1, transmit(getRSAPubKeyMod()).getData());
                return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(mod, exp));
            case 9:
                // EC_F2M
                int m = 2; // Unknown magic number...
                BigInteger F = new BigInteger(1, transmit(getECPubKeyField()).getData());
                return getECPubKey(new ECFieldF2m(m, F));
            case 11:
                // EC_FP
                F = new BigInteger(1, transmit(getECPubKeyField()).getData());
                return getECPubKey(new ECFieldFp(F));
            default:
                throw new InvalidKeySpecException("Unknown Key type");
        }
    }

    private ResponseAPDU transmit(CommandAPDU cmd) {
        return new ResponseAPDU(this.card.transmitCommand(cmd.getBytes()));
    }

    private PublicKey getECPubKey(ECField field) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger A = new BigInteger(1, transmit(getECPubKeyA()).getData());
        BigInteger B = new BigInteger(1, transmit(getECPubKeyB()).getData());

        BigInteger R = new BigInteger(1, transmit(getECPubKeyR()).getData());
        int K = (int) ByteBuffer.wrap(transmit(getECPubKeyK()).getData()).order(ByteOrder.BIG_ENDIAN).getShort();
        byte[] W = transmit(getECPubKeyW()).getData();
        byte[] G = transmit(getECPubKeyG()).getData();

        EllipticCurve curve = new EllipticCurve(field, A, B);

        ECPoint w = ECPointUtil.decodePoint(curve, W);
        ECPoint g = ECPointUtil.decodePoint(curve, G);
        ECParameterSpec domainParams = new ECParameterSpec(curve, g, R, K);

        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, domainParams));
    }

    public boolean validate(PublicKey pub) throws CardException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] challenge = new byte[127];
        rand.nextBytes(challenge);
        byte[] response = transmit(signChallenge(challenge)).getData();
        Signature verifier;

        switch (pub.getAlgorithm()) {
            case "RSA":
                verifier = Signature.getInstance("SHA1withRSA");
                break;
            case "EC":
                verifier = Signature.getInstance("SHA1withECDSA");
                break;
                default:
                    throw new NoSuchAlgorithmException("Public key has unknown algorithm type");
        }

        verifier.initVerify(pub);
        verifier.update(challenge);
        return verifier.verify(response);
    }
}
