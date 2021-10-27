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

@WebServlet(urlPatterns = "/logout")
public class LogoutServlet extends HttpServlet {

    @EJB
    private AuthenticationServiceLocal authenticationService;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getSession().setAttribute("username", null);
        resp.sendRedirect("./login");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        //nothing
    }
}
