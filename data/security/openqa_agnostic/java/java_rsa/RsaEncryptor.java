import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import javax.crypto.Cipher;

/**
 * Encrypt a file with an RSA public key, using OAEP padding.
 *
 * Usage: java RsaEncryptor publicKeyPemPath inputFile outputFile
 *
 * Exits 0 on success, 1 on failure, 3 if no provider offers the transformation.
 */
public class RsaEncryptor {

    /** SHA-256 digest length, as used by the OAEP transformation below. */
    private static final int OAEP_HASH_BYTES = 32;

    public static void main(String[] args) {
        if (args.length < 3)
            RsaPemUtils.usage("java RsaEncryptor <publicKeyPemPath> <inputFile> <outputFile>");

        String publicKeyPath = args[0];
        String inputFilePath = args[1];
        String outputFilePath = args[2];

        try {
            PublicKey publicKey = RsaPemUtils.readPublicKey(publicKeyPath);
            int modulusBits = RsaPemUtils.modulusBits(publicKey);
            System.out.println("Public key modulus size: " + modulusBits + " bits");

            Cipher cipher = RsaPemUtils.oaepCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            System.err.println("[JCA INFO] Cipher Provider: " + cipher.getProvider().getName());
            System.err.println("[JCA INFO] Cipher Provider Info: " + cipher.getProvider().getInfo());

            byte[] fileContent = Files.readAllBytes(Path.of(inputFilePath));

            // RSA encrypts one block only. OAEP takes k - 2*hLen - 2 bytes of
            // it, so say so plainly rather than emitting IllegalBlockSizeException.
            int maxBytes = modulusBits / 8 - 2 * OAEP_HASH_BYTES - 2;
            if (fileContent.length > maxBytes) {
                System.err.println("Encryption failed: " + inputFilePath + " is " + fileContent.length
                        + " bytes, but a " + modulusBits + "-bit key with OAEP/SHA-256 padding takes at most "
                        + maxBytes + " bytes");
                System.exit(1);
            }

            Files.write(Path.of(outputFilePath), cipher.doFinal(fileContent));
            System.out.println("Success: File successfully encrypted into '" + outputFilePath + "'");

        } catch (Exception e) {
            RsaPemUtils.die("Encryption failed", e);
        }
    }
}
