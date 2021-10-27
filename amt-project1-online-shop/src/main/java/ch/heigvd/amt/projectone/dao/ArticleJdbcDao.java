package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.Article;

import javax.annotation.Resource;
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
public class ArticleJdbcDao implements ArticleDaoLocal {

    private static final Logger LOG = Logger.getLogger(ArticleJdbcDao.class.getSimpleName());

    @Resource(lookup = "java:jboss/datasources/SqliteDS")
    private DataSource dataSource;

    @Override
    public boolean create(Article... articles) {

        try (Connection connection = dataSource.getConnection()) {

            connection.setAutoCommit(false);
            PreparedStatement ps = connection.prepareStatement("INSERT INTO article (name, description, price) VALUES (?, ?, ?)", Statement.RETURN_GENERATED_KEYS);

            for (Article article : articles) {
                setStatement(ps, article, 1);
                ps.addBatch();
            }

            ps.executeBatch();
            connection.commit();

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {

                // sqlite jdbc driver will only return the latest generated key
                if (generatedKeys.next()) {

                    long lastId = generatedKeys.getLong(1);
                    for (int i = articles.length - 1; i >= 0; i--) {
                        articles[i].setId(lastId--);
                    }
                }
            }

            ps.close();
            return true;
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating article.", e);
            return false;
        }
    }

    @Override
    public List<Article> findAll() {
        return findRange(0, -1);
    }

    @Override
    public List<Article> findRange(long offset, long rowCount) {

        List<Article> articles = new ArrayList<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM article ORDER BY id LIMIT ? OFFSET ?")) {

            ps.setLong(1, rowCount);
            ps.setLong(2, offset);

            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                articles.add(buildArticle(rs));
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating article.", e);
        }

        return articles;
    }

    @Override
    public long countAll() {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT COUNT(*) FROM article");
             ResultSet rs = ps.executeQuery();) {

            if (rs.next()) {
                return rs.getLong(1);
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when querying article count.", e);
        }

        return -1;
    }

    @Override
    public Article findById(Long id) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("SELECT * FROM article WHERE id = ?")) {

            ps.setLong(1, id);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return buildArticle(rs);
            }
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when creating article.", e);
        }

        return null;
    }

    @Override
    public boolean delete(Article article) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("DELETE FROM article WHERE id = ?")) {

            ps.setLong(1, article.getId());
            return 1 == ps.executeUpdate();
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when deleting article.", e);
            return false;
        }
    }

    @Override
    public boolean update(Article article) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement("UPDATE article SET name = ?, price = ? WHERE id = ?")) {

            int index = setStatement(ps, article, 0);
            ps.setLong(index, article.getId());

            return 1 == ps.executeUpdate();
        }
        catch (SQLException e) {
            LOG.log(Level.SEVERE, "Error when updating article.", e);
            return false;
        }
    }

    private Article buildArticle(ResultSet rs) throws SQLException {
        return Article.builder()
                .id(rs.getLong("id"))
                .name(rs.getString("name"))
                .description(rs.getString("description"))
                .price(rs.getBigDecimal("price"))
                .build();
    }

    private int setStatement(PreparedStatement ps, Article article, int startIndex) throws SQLException {
        ps.setString(startIndex++, article.getName());
        ps.setString(startIndex++, article.getDescription());
        ps.setBigDecimal(startIndex++, article.getPrice());
        return startIndex;
    }
}
