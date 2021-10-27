package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.dao.ArticleDaoLocal;
import ch.heigvd.amt.projectone.dao.CartDaoLocal;
import ch.heigvd.amt.projectone.dao.UserDaoLocal;
import ch.heigvd.amt.projectone.model.Article;
import ch.heigvd.amt.projectone.model.Cart;
import ch.heigvd.amt.projectone.model.User;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

@WebServlet(urlPatterns = "/cart")
public class CartServlet extends HttpServlet {

    @EJB
    private CartDaoLocal cartDao;

    @EJB
    private UserDaoLocal userDao;

    @EJB
    private ArticleDaoLocal articleDao;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String action = req.getParameter("action");
        if (action == null) {
            String username = req.getSession().getAttribute("username").toString();
            User user = userDao.findBy(username);
            Cart cart = cartDao.find(user);

            Map<Article, Long> test = cart.getItems();
            Set<Article> setArticle = test.keySet();

            req.setAttribute("articles", setArticle);
            req.getRequestDispatcher("/WEB-INF/pages/cart.jsp").forward(req, resp);
        }
        else if (action.equalsIgnoreCase("buy")) {
            doGetBuy(req, resp);
        }
        else if (action.equalsIgnoreCase("deleteAll")) {
            doGetDeleteAll(req, resp);
        }
    }

    private void doGetBuy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getSession().getAttribute("username").toString();
        User user = userDao.findBy(username);
        Cart cart = cartDao.find(user);
        cart.add(articleDao.findById(Long.parseLong(req.getParameter("id"))));
        cartDao.update(cart);
        resp.sendRedirect("./articles");
    }

    private void doGetDeleteAll(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getSession().getAttribute("username").toString();
        User user = userDao.findBy(username);
        Cart cart = cartDao.find(user);
        cartDao.delete(cart);
        resp.sendRedirect("./articles");

    }
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        //req.getRequestDispatcher("/WEB-INF/pages/register.jsp").forward(req, resp);
        //resp.sendRedirect("./articles");
    }
}
