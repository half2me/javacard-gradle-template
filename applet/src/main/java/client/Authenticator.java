package client;

import com.licel.jcardsim.io.JavaCardInterface;

import javax.smartcardio.CardException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class Authenticator {
    private CryptoCardClient client;

    private Map<PublicKey, String> db;

    public Authenticator(JavaCardInterface card) {
        client = new CryptoCardClient(card);
        db = new HashMap<PublicKey, String>();
    }

    public boolean registerNewCard(String name) throws NoSuchAlgorithmException, CardException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        PublicKey key = client.getPubKey();
        if (client.validate(key)) {
            db.put(key, name);
            return true;
        }
        return false;
    }

    public boolean deleteCard(String name) {
        PublicKey key = null;

        for (Map.Entry<PublicKey, String> card: db.entrySet()) {
            if (card.getValue().equals(name)) {
                key = card.getKey();
                break;
            }
        }

        if (key != null) {
            db.remove(key);
            return true;
        }

        return false;
    }

    public String identifyCard() throws Exception {
        PublicKey key = client.getPubKey();
        if (client.validate(key)) { return db.get(key); }
        throw new Exception("Invalid Signature");
    }
}
