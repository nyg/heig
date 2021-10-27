package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.User;
import ch.heigvd.amt.projectone.service.AuthenticationServiceLocal;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

@Stateless
public class UserJdbcDao implements UserDaoLocal {

    private static final Logger LOG = Logger.getLogger(UserJdbcDao.class.getSimpleName());
    private static final String INSERT_USER = "INSERT INTO user (username, firstname, lastname, email, password, admin) VALUES (?, ?, ?, ?, ?, ?)";

    @Resource(lookup = "java:jboss/datasources/SqliteDS")
    private DataSource dataSource;

    @EJB
    private AuthenticationServiceLocal authenticationService;

    @Override
    public boolean create(User... users) {

        try (Connection connection = dataSource.getConnection()) {

            connection.setAutoCommit(false);
            PreparedStatement ps = connection.prepareStatement(INSERT_USER, Statement.RETURN_GENERATED_KEYS);

            for (User user : users) {
                setStatement(ps, user, 1);
                ps.addBatch();
            }

            ps.executeBatch();
            connection.commit();

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {

                // sqlite jdbc driver will only return the latest generated key
                if (generatedKeys.next()) {

                    long lastId = generatedKeys.getLong(1);
                    for (int i = users.length - 1; i >= 0; i--) {
                        users[i].setId(lastId--);
                    }
                }
            }

            ps.close();
            return true;
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating user.", e);
            return false;
        }
    }

    @Override
    public List<User> findAll() {

        List<User> users = new ArrayList<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM user");
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                users.add(buildUser(rs));
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating user.", e);
        }

        return users;
    }

    @Override
    public User findBy(Long id) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM user WHERE id = ?")) {

            ps.setLong(1, id);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return buildUser(rs);
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating user.", e);
        }

        return null;
    }

    @Override
    public User findBy(String username) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM user WHERE username = ?")) {

            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return buildUser(rs);
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating user.", e);
        }

        return null;
    }

    @Override
    public boolean delete(User user) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("DELETE FROM user WHERE id = ?")) {

            ps.setLong(1, user.getId());
            return 1 == ps.executeUpdate();
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when deleting user.", e);
            return false;
        }
    }

    @Override
    public boolean update(User user) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("UPDATE user SET username = ?, firstname = ?, lastname = ?, email = ?, password = ?, admin = ? WHERE id = ?")) {

            int index = setStatement(ps, user, 1);
            ps.setLong(index, user.getId());

            return 1 == ps.executeUpdate();
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when updating user.", e);
            return false;
        }
    }

    private User buildUser(ResultSet rs) throws SQLException {
        return User.builder()
                .id(rs.getLong("id"))
                .username(rs.getString("username"))
                .firstname(rs.getString("firstname"))
                .lastname(rs.getString("lastname"))
                .email(rs.getString("email"))
                .password(rs.getString("password"))
                .admin(rs.getBoolean("admin"))
                .build();
    }

    private int setStatement(PreparedStatement ps, User user, int startIndex) throws SQLException {
        ps.setString(startIndex++, user.getUsername());
        ps.setString(startIndex++, user.getFirstname());
        ps.setString(startIndex++, user.getLastname());
        ps.setString(startIndex++, user.getEmail());
        ps.setString(startIndex++, authenticationService.hashPassword(user.getPassword()));
        ps.setBoolean(startIndex++, user.isAdmin());
        return startIndex;
    }
}
