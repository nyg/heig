package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.dao.UserDaoLocal;
import ch.heigvd.amt.projectone.model.User;
import ch.heigvd.amt.projectone.service.AuthenticationServiceLocal;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = "login")
public class LoginServlet extends HttpServlet {

    @EJB
    private UserDaoLocal userDao;

    @EJB
    private AuthenticationServiceLocal authenticationService;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/pages/login.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (username == null || password == null) {
            req.setAttribute("error", "No username or password provided.");
            req.getRequestDispatcher("/WEB-INF/pages/login.jsp").forward(req, resp);
            return;
        }

        User user = userDao.findBy(username);
        if (authenticationService.checkPasswords(password, user.getPassword())) {

            // Authentication is successful, set the session.
            req.getSession().setAttribute("username", user.getUsername());

            // Redirect to home page or target url, if set.
            String targetUrl = req.getParameter("targetUrl");
            resp.sendRedirect(targetUrl == null ? "./articles" : targetUrl);
        }
        else {
            req.setAttribute("error", "Invalid password.");
            req.getRequestDispatcher("/WEB-INF/pages/login.jsp").forward(req, resp);
        }
    }
}
