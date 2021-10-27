package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.service.GenerationServiceLocal;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = GenerateServlet.URL)
public class GenerateServlet extends HttpServlet {

    public static final String URL = "/generate";
    public static final String JSP = "/WEB-INF/pages/generate.jsp";

    @EJB
    GenerationServiceLocal generationService;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher(JSP).forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        int entryCount = Integer.parseInt(req.getParameter("entry-count"));
        generationService.generate(entryCount);

        req.setAttribute("result", "Entities generated successfully.");
        req.getRequestDispatcher(JSP).forward(req, resp);
    }
}
