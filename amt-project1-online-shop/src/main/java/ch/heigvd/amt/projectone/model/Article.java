package ch.heigvd.amt.projectone.model;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;

@Builder
@Setter
@Getter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Article {

    @EqualsAndHashCode.Include
    private Long id;

    private String name;
    private String description;
    private BigDecimal price;
}
