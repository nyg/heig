package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.dao.UserDaoLocal;
import ch.heigvd.amt.projectone.model.User;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = "/register")
public class RegisterServlet extends HttpServlet {

    @EJB
    private UserDaoLocal userDao;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/pages/register.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String username = req.getParameter("username");
        String firstname = req.getParameter("firstname");
        String lastname = req.getParameter("lastname");
        String email = req.getParameter("email");
        String password = req.getParameter("password");

        boolean success;
        if (username == null || firstname == null || lastname == null || email == null || password == null) {
            success = false;
        }
        else if (userDao.findBy(username) != null) {
            success = false;
        }
        else {
            success = userDao.create(User.builder()
                    .username(username)
                    .firstname(firstname)
                    .lastname(lastname)
                    .email(email)
                    .password(password)
                    .build());
        }

        req.setAttribute("success", success);
        req.getRequestDispatcher("/WEB-INF/pages/register.jsp").forward(req, resp);
    }
}
