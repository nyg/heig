package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.Article;
import ch.heigvd.amt.projectone.model.Cart;
import ch.heigvd.amt.projectone.model.User;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Stateless
public class CartJdbcDao implements CartDaoLocal {

    private static final Logger LOG = Logger.getLogger(CartJdbcDao.class.getSimpleName());

    @Resource(lookup = "java:jboss/datasources/SqliteDS")
    private DataSource dataSource;

    @EJB
    private ArticleDaoLocal articleDao;

    public boolean create(Cart... carts) {

        try (Connection connection = dataSource.getConnection()) {

            connection.setAutoCommit(false);
            PreparedStatement ps = connection.prepareStatement("INSERT INTO cart (user, article, quantity) VALUES (?, ?, ?)");

            for (Cart cart : carts) {

                for (Map.Entry<Article, Long> item : cart.getItems().entrySet()) {

                    ps.setLong(1, cart.getUser().getId());
                    ps.setLong(2, item.getKey().getId());
                    ps.setLong(3, item.getValue());

                    ps.addBatch();
                }
            }

            ps.executeBatch();
            connection.commit();

            return true;
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating cart.", e);
            return false;
        }
    }

    public Cart find(User user) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM cart WHERE user = ?")) {

            ps.setLong(1, user.getId());
            ResultSet rs = ps.executeQuery();

            Cart cart = Cart.builder().user(user).build();

            while (rs.next()) {
                Article article = articleDao.findById(rs.getLong("article"));
                cart.add(article, rs.getLong("quantity"));
            }

            return cart;
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when deleting article from cart.", e);
            return null;
        }
    }

    public boolean update(Cart cart) {
        delete(cart);
        create(cart);
        return true;
    }

    public boolean delete(Cart cart) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("DELETE FROM cart WHERE user = ?")) {

            ps.setLong(1, cart.getUser().getId());
            ps.executeUpdate();

            return true;
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when deleting cart.", e);
            return false;
        }
    }
}
