import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Generate an RSA key pair of the requested size and store it as PEM.
 *
 * Usage: java RsaKeyGeneratorTest [bitSize]
 *
 * Exits 0 on success, 1 if the environment refuses the requested key size. A
 * FIPS 140-3 validated provider must refuse anything below 2048 bits: NIST SP
 * 800-131A Rev. 2 disallows RSA key *generation* below that, and permits
 * 1024-bit moduli for legacy signature verification only.
 */
public class RsaKeyGeneratorTest {

    public static void main(String[] args) {
        int bitSize = 2048;

        if (args.length > 0) {
            try {
                bitSize = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                RsaPemUtils.usage("java RsaKeyGeneratorTest [bitSize]");
            }
        }

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

            // Report the provider before initialize(), so that a refused key
            // size still tells us which provider did the refusing.
            System.err.println("[JCA INFO] Provider Name: " + keyPairGen.getProvider().getName());
            System.err.println("[JCA INFO] Provider Info: " + keyPairGen.getProvider().getInfo());

            keyPairGen.initialize(bitSize);

            System.out.println("Generating RSA " + bitSize + "-bit key pair...");
            KeyPair pair = keyPairGen.generateKeyPair();

            RsaPemUtils.writePem(pair.getPublic().getEncoded(), RsaPemUtils.PUBLIC_KEY, "public_key.pem");
            System.out.println("Success: Public key saved to 'public_key.pem'");

            RsaPemUtils.writePem(pair.getPrivate().getEncoded(), RsaPemUtils.PRIVATE_KEY, "private_key.pem");
            System.out.println("Success: Private key saved to 'private_key.pem'");

            System.out.println("Modulus size: " + RsaPemUtils.modulusBits(pair.getPublic()) + " bits");

        } catch (Exception e) {
            // Exception, not NoSuchAlgorithmException/IOException: a rejected
            // key size arrives as an unchecked InvalidParameterException, and
            // letting that escape main() would dump a stack trace instead of
            // reporting a legitimate, expected refusal.
            RsaPemUtils.die("Key generation of " + bitSize + " bits failed", e);
        }
    }
}
