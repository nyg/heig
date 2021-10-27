package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.dao.ArticleDaoLocal;
import ch.heigvd.amt.projectone.dao.UserDaoLocal;
import ch.heigvd.amt.projectone.model.Article;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@WebServlet(urlPatterns = ArticleServlet.URL)
public class ArticleServlet extends HttpServlet {

    public static final String URL = "/articles";
    public static final String JSP = "/WEB-INF/pages/index.jsp";

    private static final long DEFAULT_ARTICLE_COUNT_PER_PAGE = 21;

    @EJB
    private UserDaoLocal userDao;

    @EJB
    private ArticleDaoLocal articleDao;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        // get new pageNumber
        long pageNumber = getLongParameter(req, "pageNumber", 1);
        if (pageNumber <= 0) {
            pageNumber = 1;
        }

        // get number of articles to display on the page
        long articleCountPerPage = getLongParameter(req, "articleCount", DEFAULT_ARTICLE_COUNT_PER_PAGE);

        // find total article count (in database) and compute total page count
        long totalArticleCount = articleDao.countAll();
        long pageCount = totalArticleCount / articleCountPerPage;

        List<Article> articles = articleDao.findRange((pageNumber - 1) * articleCountPerPage, articleCountPerPage);
        req.setAttribute("articles", articles);
        req.setAttribute("pageNumber", pageNumber);
        req.setAttribute("pageCount", pageCount);

        req.getRequestDispatcher(JSP).forward(req, resp);
    }

    private long getLongParameter(HttpServletRequest request, String name, long defaultValue) {

        try {
            return Long.parseLong(request.getParameter(name));
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
