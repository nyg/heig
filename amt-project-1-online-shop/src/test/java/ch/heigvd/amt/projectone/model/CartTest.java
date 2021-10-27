package ch.heigvd.amt.projectone.model;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CartTest {

    private static final User USER = User.builder().username("paul").build();

    private static final Article ARTICLE;
    private static final Long QUANTITY = 6L;

    static {
        ARTICLE = Article.builder().name("usb-key").price(new BigDecimal(123.4)).build();
    }

    @Test
    void itShouldBePossibleToCreateShoppingCarts() {

        Cart cart = Cart.builder().user(USER).build();
        cart.add(ARTICLE, QUANTITY);

        assertNotNull(cart);
        assertEquals(USER, cart.getUser());
        assertEquals(QUANTITY, cart.getItems().get(ARTICLE));
    }
}