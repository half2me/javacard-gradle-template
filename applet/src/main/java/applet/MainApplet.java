package applet;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.RandomData;

public class MainApplet extends Applet implements ISO7816
{
	private static final short SCRATCHPAD_SIZE = 256;

	private byte[] scratchpad = JCSystem.makeTransientByteArray(SCRATCHPAD_SIZE, JCSystem.CLEAR_ON_DESELECT);
	protected KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_F2M_163);

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new MainApplet(bArray, bOffset, bLength);
	}
	
	public MainApplet(byte[] buffer, short offset, byte length)
	{
        kp.genKeyPair();
		register();
	}

	public void process(APDU apdu)
	{
		byte[] apduBuffer = apdu.getBuffer();
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		byte ins = apduBuffer[ISO7816.OFFSET_INS];
		short lc = (short)apduBuffer[ISO7816.OFFSET_LC];
		short p1 = (short)apduBuffer[ISO7816.OFFSET_P1];
		short p2 = (short)apduBuffer[ISO7816.OFFSET_P2];

        if (this.selectingApplet()) { return; }

        switch (ins) {
            case 0x00:
                sendPublicKey(apdu);
                return;
            default:
                ISOException.throwIt (ISO7816.SW_INS_NOT_SUPPORTED);
        }
	}

    private void sendPublicKey(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        PublicKey pk = kp.getPublic();
        byte type = pk.getType();
        short size = pk.getSize();

        //Util.arrayCopyNonAtomic(tmpBuffer, (short)0, apduBuffer, (short)0, BUFFER_SIZE);
        //apdu.setOutgoingAndSend((short)0, BUFFER_SIZE);
    }
}
