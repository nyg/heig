package ch.heig.amt.business.server.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.io.Serializable;

@Entity(name = "article")
@Getter
@Setter
public class ArticleEntity implements Serializable {

    @Id
    private long id;

    private String name;
    private String description;
    private int price;
}
