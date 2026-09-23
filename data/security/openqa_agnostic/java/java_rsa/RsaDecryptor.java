import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import javax.crypto.Cipher;

/**
 * Decrypt a file with an RSA private key, using OAEP padding.
 *
 * Usage: java RsaDecryptor privateKeyPemPath encryptedFile outputFile
 *
 * Exits 0 on success, 1 on failure, 3 if no provider offers the transformation.
 */
public class RsaDecryptor {

    public static void main(String[] args) {
        if (args.length < 3)
            RsaPemUtils.usage("java RsaDecryptor <privateKeyPemPath> <encryptedFile> <outputFile>");

        String privateKeyPath = args[0];
        String encryptedFilePath = args[1];
        String outputFilePath = args[2];

        try {
            PrivateKey privateKey = RsaPemUtils.readPrivateKey(privateKeyPath);
            System.out.println("Private key modulus size: " + RsaPemUtils.modulusBits(privateKey) + " bits");

            // Must match the transformation used to encrypt.
            Cipher cipher = RsaPemUtils.oaepCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            System.err.println("[JCA INFO] Cipher Provider: " + cipher.getProvider().getName());
            System.err.println("[JCA INFO] Cipher Provider Info: " + cipher.getProvider().getInfo());

            byte[] encryptedContent = Files.readAllBytes(Path.of(encryptedFilePath));
            Files.write(Path.of(outputFilePath), cipher.doFinal(encryptedContent));
            System.out.println("Success: File successfully decrypted into '" + outputFilePath + "'");

        } catch (Exception e) {
            RsaPemUtils.die("Decryption failed", e);
        }
    }
}
