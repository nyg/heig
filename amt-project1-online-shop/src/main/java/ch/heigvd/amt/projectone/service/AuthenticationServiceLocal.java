package ch.heigvd.amt.projectone.service;

import javax.ejb.Local;

@Local
public interface AuthenticationServiceLocal {

    String hashPassword(String password);

    boolean checkPasswords(String plainText, String hash);
}
