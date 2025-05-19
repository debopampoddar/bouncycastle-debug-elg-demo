package com.debopam;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Iterator;

public class DebugElgDemo {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: java -jar bouncycastle-debug-elg-demo.jar <secret-keyring.asc> <encrypted.pgp> <passphrase>");
            System.exit(1);
        }
        String keyRingFile = args[0];
        String inputFile = args[1];
        char[] passphrase = args[2].toCharArray();

        // Register the debug-enabled BC provider
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Provider: " + Security.getProvider("BC"));

        // Load secret keyring
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new FileInputStream(keyRingFile)),
                new JcaKeyFingerprintCalculator());

        // Open encrypted file
        InputStream in = PGPUtil.getDecoderStream(new FileInputStream(inputFile));
        PGPObjectFactory pgpFact = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList encList = null;
        Object obj = pgpFact.nextObject();
        if (obj instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) obj;
        } else {
            encList = (PGPEncryptedDataList) pgpFact.nextObject();
        }

        // Find the secret key matching the encrypted data's key ID
        Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        while (it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            long keyID = pbe.getKeyID();
            PGPSecretKey secretKey = pgpSec.getSecretKey(keyID);
            if (secretKey != null) {
                sKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder()
                                .setProvider("BC")
                                .build(passphrase));
                break;
            }
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        // Decrypt
        InputStream clear = pbe.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC").build(sKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        Object message = plainFact.nextObject();
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
            System.out.println("Decrypted message:");
            System.out.println(new String(out.toByteArray()));
        } else {
            System.err.println("Unexpected message type: " + message.getClass());
        }

        if (pbe.isIntegrityProtected()) {
            System.out.println("Integrity check passed: " + pbe.verify());
        }
    }
}
