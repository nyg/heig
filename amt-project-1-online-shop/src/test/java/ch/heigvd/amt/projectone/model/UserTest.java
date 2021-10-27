package ch.heigvd.amt.projectone.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    public static final String USERNAME = "username-one";

    @Test
    void itShouldBePossibleToCreateUsers() {
        User user = User.builder()
                .username(USERNAME)
                .build();
        assertNotNull(user);
        assertEquals(USERNAME, user.getUsername());
    }
}