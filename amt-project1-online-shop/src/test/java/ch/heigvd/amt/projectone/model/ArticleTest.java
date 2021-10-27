package ch.heigvd.amt.projectone.model;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ArticleTest {

    private static final Long ID = 12345L;
    private static final String NAME = "article-name";
    private static final String DESCRIPTION = "article-description";
    private static final BigDecimal PRICE = new BigDecimal(10.1);

    @Test
    void itShouldBePossibleToBuildAnArticle() {

        Article article = Article.builder()
                .id(ID)
                .name(NAME)
                .description(DESCRIPTION)
                .price(PRICE)
                .build();

        assertNotNull(article);
        assertEquals(ID, article.getId());
        assertEquals(NAME, article.getName());
        assertEquals(DESCRIPTION, article.getDescription());
        assertEquals(PRICE, article.getPrice());
    }

    @Test
    void itShouldBePossibleToCreateAnArticle() {

        Article article = Article.builder().build();
        article.setId(ID);
        article.setName(NAME);
        article.setDescription(DESCRIPTION);
        article.setPrice(PRICE);

        assertNotNull(article);
        assertEquals(ID, article.getId());
        assertEquals(NAME, article.getName());
        assertEquals(DESCRIPTION, article.getDescription());
        assertEquals(PRICE, article.getPrice());
    }

    @Test
    void itShouldBePossibleToCompareTwoArticles() {

        Article a1 = Article.builder().id(1L).description(DESCRIPTION).price(PRICE).build();
        Article a2 = Article.builder().id(1L).description(DESCRIPTION + DESCRIPTION).build();
        Article a3 = Article.builder().id(2L).description(DESCRIPTION + DESCRIPTION).build();

        assertEquals(a1, a2);
        assertNotEquals(a2, a3);
    }
}