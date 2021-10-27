package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.User;

import javax.ejb.Local;
import java.util.List;

@Local
public interface UserDaoLocal {

    User findBy(Long id);

    User findBy(String username);

    boolean create(User... users);

    List<User> findAll();

    boolean delete(User object);

    boolean update(User object);
}
