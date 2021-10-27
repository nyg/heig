package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.Article;

import javax.ejb.Local;
import java.util.List;

@Local
public interface ArticleDaoLocal {

    long countAll();

    Article findById(Long id);

    List<Article> findAll();

    List<Article> findRange(long offset, long rowCount);

    boolean create(Article... articles);

    boolean delete(Article article);

    boolean update(Article article);
}
