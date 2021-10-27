package ch.heigvd.amt.projectone.service;

import javax.ejb.Stateless;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Stateless
public class AuthenticationService implements AuthenticationServiceLocal {

    private static final MessageDigest DIGEST;

    static {
        try {
            DIGEST = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError();
        }
    }

    @Override
    public String hashPassword(String password) {
        byte[] hash = DIGEST.digest(password.getBytes(StandardCharsets.UTF_8));
        return String.format("%064x", new BigInteger(1, hash));

    }

    @Override
    public boolean checkPasswords(String plainText, String hash) {
        return hashPassword(plainText).equals(hash);
    }
}
