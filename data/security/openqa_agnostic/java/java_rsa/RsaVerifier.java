import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Verify a SHA256withRSA signature over a file.
 *
 * Usage: java RsaVerifier publicKeyPemPath originalFile signatureFile
 *
 * Exit codes are three-way on purpose, so that a caller can tell a rejected
 * signature apart from a broken run: 0 the signature is valid, 1 the signature
 * is invalid, 2 verification could not be carried out.
 */
public class RsaVerifier {

    private static final int VALID = 0;
    private static final int INVALID = 1;
    private static final int ERROR = 2;

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java RsaVerifier <publicKeyPemPath> <originalFile> <signatureFile>");
            System.exit(ERROR);
        }

        String publicKeyPath = args[0];
        String originalFilePath = args[1];
        String signaturePath = args[2];

        try {
            PublicKey publicKey = RsaPemUtils.readPublicKey(publicKeyPath);
            System.out.println("Public key modulus size: " + RsaPemUtils.modulusBits(publicKey) + " bits");

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            System.err.println("[JCA INFO] Signature Provider: " + signature.getProvider().getName());
            System.err.println("[JCA INFO] Signature Provider Info: " + signature.getProvider().getInfo());

            signature.update(Files.readAllBytes(Path.of(originalFilePath)));
            byte[] signatureBytes = Files.readAllBytes(Path.of(signaturePath));

            if (signature.verify(signatureBytes)) {
                System.out.println("VERIFICATION SUCCESS: The signature is VALID. The file has not been modified.");
                System.exit(VALID);
            }
            System.out.println("VERIFICATION FAILURE: The signature is INVALID. The file or key mismatch detected.");
            System.exit(INVALID);

        } catch (Exception e) {
            System.err.println("Verification failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(ERROR);
        }
    }
}
