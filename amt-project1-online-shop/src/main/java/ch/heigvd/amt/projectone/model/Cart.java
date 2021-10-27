package ch.heigvd.amt.projectone.model;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Builder
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Cart {

    @EqualsAndHashCode.Include
    private User user;

    private final Map<Article, Long> items = new HashMap<>();

    public void add(Article article) {
        add(article, 1);
    }

    public void add(Article article, long addedQuantity) {
        long currentQuantity = items.getOrDefault(article, 0L);
        items.put(article, currentQuantity + addedQuantity);
    }
}
