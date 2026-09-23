import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Sign a file with an RSA private key, using SHA256withRSA.
 *
 * Usage: java RsaSigner privateKeyPemPath fileToSign signatureOutputFile
 *
 * Exits 0 on success, 1 on any failure.
 */
public class RsaSigner {

    public static void main(String[] args) {
        if (args.length < 3)
            RsaPemUtils.usage("java RsaSigner <privateKeyPemPath> <fileToSign> <signatureOutputFile>");

        String privateKeyPath = args[0];
        String filePathToSign = args[1];
        String signaturePath = args[2];

        try {
            PrivateKey privateKey = RsaPemUtils.readPrivateKey(privateKeyPath);
            System.out.println("Private key modulus size: " + RsaPemUtils.modulusBits(privateKey) + " bits");

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);

            System.err.println("[JCA INFO] Signature Provider: " + signature.getProvider().getName());
            System.err.println("[JCA INFO] Signature Provider Info: " + signature.getProvider().getInfo());

            signature.update(Files.readAllBytes(Path.of(filePathToSign)));
            Files.write(Path.of(signaturePath), signature.sign());
            System.out.println("Success: Digital signature generated and saved to '" + signaturePath + "'");

        } catch (Exception e) {
            RsaPemUtils.die("Signing failed", e);
        }
    }
}
