import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * PEM and error handling helpers shared by the RSA command line tools.
 *
 * The tools are deliberately separate programs, so that every step of the RSA
 * life cycle runs in its own JVM and re-does the JCA provider selection. Only
 * the code they have in common lives here.
 */
final class RsaPemUtils {

    static final String PUBLIC_KEY = "PUBLIC KEY";
    static final String PRIVATE_KEY = "PRIVATE KEY";

    /** RSAES-OAEP, the only key transport scheme SP 800-56B Rev. 2 approves. */
    static final String OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /** Exit status for "this environment has no provider for the transformation". */
    static final int UNSUPPORTED = 3;

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN ([A-Z ]+)-----(.*?)-----END \\1-----", Pattern.DOTALL);

    private RsaPemUtils() {
    }

    /** Write raw DER key bytes as PEM, Base64 wrapped at 64 characters. */
    static void writePem(byte[] keyBytes, String headerType, String file) throws IOException {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(keyBytes);
        String pem = "-----BEGIN " + headerType + "-----\n" + body + "\n-----END " + headerType + "-----\n";
        Files.write(Path.of(file), pem.getBytes(StandardCharsets.UTF_8));
    }

    static PublicKey readPublicKey(String file) throws Exception {
        byte[] der = readPemBody(file, PUBLIC_KEY);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    static PrivateKey readPrivateKey(String file) throws Exception {
        byte[] der = readPemBody(file, PRIVATE_KEY);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /**
     * Decode the Base64 body of a PEM file, insisting that the block really is
     * of the expected type. Reporting "found PRIVATE KEY" beats letting the
     * Base64 decoder complain about the header it was never meant to see.
     */
    private static byte[] readPemBody(String file, String expectedType) throws IOException {
        String content = Files.readString(Path.of(file), StandardCharsets.UTF_8);
        Matcher m = PEM.matcher(content);
        if (!m.find())
            throw new IOException(file + ": no PEM block found, expected a " + expectedType);
        if (!expectedType.equals(m.group(1)))
            throw new IOException(file + ": expected a " + expectedType + ", found " + m.group(1));
        return Base64.getDecoder().decode(m.group(2).replaceAll("\\s", ""));
    }

    /**
     * The OAEP cipher, or exit {@link #UNSUPPORTED} if no provider offers it.
     *
     * A missing transformation is a property of the environment, not a defect
     * in the caller, so it gets its own exit status: a driver can then skip the
     * round trip instead of reporting a failure the machine cannot act on. The
     * service survey spells out what is on offer instead.
     */
    static Cipher oaepCipher() {
        try {
            return Cipher.getInstance(OAEP);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Unsupported: no provider offers " + OAEP);
            System.err.println("RSA services offered by the registered providers:");
            System.err.print(rsaServices());
            System.exit(UNSUPPORTED);
            return null;    // not reached
        }
    }

    /** Modulus size in bits, for reporting whether a key is FIPS capable. */
    static int modulusBits(Key key) {
        return ((RSAKey) key).getModulus().bitLength();
    }

    /**
     * Report a failure and leave with a non-zero status. Every tool needs this:
     * a stack trace on its own still exits 0, which makes the failure invisible
     * to any script driving the tool.
     */
    static void die(String what, Exception e) {
        System.err.println(what + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        // "no provider supports X" on its own says nothing about what the
        // environment does support, which is the whole question in FIPS mode.
        if (e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException) {
            System.err.println("RSA services offered by the registered providers:");
            System.err.print(rsaServices());
        }
        System.exit(1);
    }

    /** Every RSA service the registered providers expose, grouped by provider. */
    static String rsaServices() {
        StringBuilder sb = new StringBuilder();
        for (Provider p : Security.getProviders()) {
            List<String> found = new ArrayList<>();
            for (Provider.Service s : p.getServices()) {
                if (!s.getAlgorithm().toUpperCase(Locale.ROOT).contains("RSA"))
                    continue;
                String entry = s.getType() + "." + s.getAlgorithm();
                // A provider registers one "Cipher.RSA" service for every
                // transformation it can do, so the padding list is the only
                // place that says whether OAEP is among them.
                if ("Cipher".equals(s.getType()))
                    entry += " [modes=" + s.getAttribute("SupportedModes")
                            + " paddings=" + s.getAttribute("SupportedPaddings") + "]";
                found.add(entry);
            }
            if (found.isEmpty())
                continue;
            Collections.sort(found);
            sb.append("  ").append(p.getName()).append(": ").append(String.join(", ", found)).append('\n');
        }
        return sb.length() == 0 ? "  (no provider offers any RSA service)\n" : sb.toString();
    }

    /** Print usage on stderr and leave with a non-zero status. */
    static void usage(String text) {
        System.err.println("Usage: " + text);
        System.exit(1);
    }
}
