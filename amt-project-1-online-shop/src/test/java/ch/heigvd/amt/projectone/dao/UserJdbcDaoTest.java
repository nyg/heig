package ch.heigvd.amt.projectone.dao;

import ch.heigvd.amt.projectone.model.User;
import ch.heigvd.amt.projectone.service.AuthenticationServiceLocal;
import org.arquillian.container.chameleon.deployment.api.DeploymentParameters;
import org.arquillian.container.chameleon.deployment.maven.MavenBuild;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ejb.EJB;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Arquillian.class)
@MavenBuild
@DeploymentParameters(testable = true)
public class UserJdbcDaoTest {

    private static final String PWD = "mypassword";

    @EJB
    private UserDaoLocal userDao;

    @EJB
    private AuthenticationServiceLocal authenticationService;

    @Test
    //@Transactional(TransactionMode.ROLLBACK)
    public void itShouldBePossibleToCreateAUser() {

        User user = User.builder().username("jean").password(PWD).build();
        boolean userCreated = userDao.create(user);
        assertTrue(userCreated);
        assertNotNull(user.getId());

        userDao.delete(user);
    }

    @Test
    //@Transactional(TransactionMode.ROLLBACK)
    public void itShouldBePossibleToDeleteAUser() {

        User user = User.builder().username("jean").password(PWD).build();
        userDao.create(user);

        boolean userDelete = userDao.delete(user);
        assertTrue(userDelete);
    }

    @Test
    //@Transactional(TransactionMode.ROLLBACK)
    public void itShouldBePossibleToUpdateAUser() {

        User user = User.builder().username("jean").password(PWD).build();
        userDao.create(user);

        user.setFirstname("Jean");
        user.setLastname("Dupond");
        user.setEmail("jean@dupond.fr");
        user.setPassword("newPwd");
        user.setAdmin(true);

        boolean userUpdated = userDao.update(user);
        assertTrue(userUpdated);

        User userVerification = userDao.findBy(user.getId());
        assertEquals(user.getFirstname(), userVerification.getFirstname());
        assertEquals(user.getLastname(), userVerification.getLastname());
        assertEquals(user.getEmail(), userVerification.getEmail());
        assertEquals(authenticationService.hashPassword(user.getPassword()), userVerification.getPassword());
        assertEquals(user.isAdmin(), userVerification.isAdmin());

        userDao.delete(user);
        userDao.delete(userVerification);
    }

    @Test
    //@Transactional(TransactionMode.ROLLBACK)
    public void itShouldBePossibleToFindAllUsers() {

        User user1 = User.builder().username("jean").firstname("Jean").lastname("Dupond").password(PWD).build();
        User user2 = User.builder().username("jack").firstname("Jack").lastname("Smith").password(PWD).build();

        userDao.create(user1);
        userDao.create(user2);

        List<User> users = userDao.findAll();
        assertEquals(2, users.size());

        userDao.delete(user1);
        userDao.delete(user2);
    }
}