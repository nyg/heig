package ch.heigvd.amt.projectone.service;

import ch.heigvd.amt.projectone.dao.ArticleDaoLocal;
import ch.heigvd.amt.projectone.dao.CartDaoLocal;
import ch.heigvd.amt.projectone.dao.UserDaoLocal;
import ch.heigvd.amt.projectone.model.Article;
import ch.heigvd.amt.projectone.model.Cart;
import ch.heigvd.amt.projectone.model.User;
import com.github.javafaker.Beer;
import com.github.javafaker.Faker;
import com.github.javafaker.Name;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.math.BigDecimal;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

@Stateless
public class GenerationService implements GenerationServiceLocal {

    private static final Logger LOG = Logger.getLogger(GenerationService.class.getSimpleName());
    private static final ThreadLocalRandom RANDOM = ThreadLocalRandom.current();

    private static final int BATCH_COUNT = 10000;
    private static final int CART_MAX_ARTICLE_COUNT = 6;

    @EJB
    private UserDaoLocal userDao;

    @EJB
    private ArticleDaoLocal articleDao;

    @EJB
    private CartDaoLocal cartDao;

    private Faker faker = new Faker();

    @Override
    public void generate(int count) {

        int i = count;
        while (i > 0) {

            int batchCount = Math.min(i, BATCH_COUNT);
            i -= BATCH_COUNT;

            User[] users = new User[batchCount];
            Article[] articles = new Article[batchCount];
            Cart[] carts = new Cart[batchCount];

            // generate batch of users and articles
            for (int j = 0; j < batchCount; j++) {
                users[j] = randomUser();
                articles[j] = randomArticle();
            }

            // persist batch
            boolean usersCreated = userDao.create(users);
            if (!usersCreated) {
                i += batchCount;
                continue; // skip batch
            }

            articleDao.create(articles);

            // generate cart for each user
            for (int j = 0; j < batchCount; j++) {

                carts[j] = Cart.builder().user(users[j]).build();

                // choose a random number of random articles for each cart
                int articleCount = RANDOM.nextInt(1, CART_MAX_ARTICLE_COUNT);
                for (int k = 0; k < articleCount; k++) {
                    carts[j].add(articles[RANDOM.nextInt(batchCount)]);
                }
            }

            // persist batch
            cartDao.create(carts);
        }
    }

    private Article randomArticle() {

        Beer beer = faker.beer();

        return Article.builder()
                .name(beer.name())
                .price(new BigDecimal(faker.number().randomDouble(2, 0, 10)))
                .description(beer.style())
                .build();
    }

    private User randomUser() {

        Name name = faker.name();
        String firstname = name.firstName();
        String lastname = name.lastName();
        String username = String.format("%s.%s.%d", firstname, lastname, RANDOM.nextInt(100, 1000)).toLowerCase();
        String email = String.format("%s@amt.ch", username);

        return User.builder()
                .username(username)
                .firstname(firstname)
                .lastname(lastname)
                .email(email)
                .admin(faker.bool().bool())
                .password("pwd")
                .build();
    }
}
