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

@WebServlet(urlPatterns = "/user")
public class UserServlet extends HttpServlet {

    @EJB
    private UserDaoLocal userDao;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String username = req.getSession().getAttribute("username").toString();
        User user = userDao.findBy(username);

        req.setAttribute("username", user.getUsername());
        req.setAttribute("firstname", user.getFirstname());
        req.setAttribute("lastname", user.getLastname());
        req.setAttribute("email", user.getEmail());
        req.setAttribute("password", user.getPassword());

        req.getRequestDispatcher("/WEB-INF/pages/user.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String username = req.getSession().getAttribute("username").toString();
        User user = userDao.findBy(username);

        user.setFirstname(req.getParameter("firstname"));
        user.setLastname(req.getParameter("lastname"));
        user.setPassword(req.getParameter("password"));
        user.setEmail(req.getParameter("email"));

        boolean updated = userDao.update(user);

        req.setAttribute("success", updated);
        resp.sendRedirect("./articles");
    }
}
