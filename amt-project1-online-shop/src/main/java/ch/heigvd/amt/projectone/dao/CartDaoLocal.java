package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.Cart;
import ch.heigvd.amt.projectone.model.User;

import javax.ejb.Local;

@Local
public interface CartDaoLocal {

    boolean create(Cart... carts);

    Cart find(User user);

    boolean update(Cart cart);

    boolean delete(Cart cart);
}
