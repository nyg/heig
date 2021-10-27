package ch.heigvd.amt.projectone.filter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This filter's goal is to intercept all requests and check if they require the
 * user to be authenticated or not.
 *
 * If authentication is required but user is not so, we redirect to the login
 * page. Otherwise the request can continue through the filter chain.
 */
@WebFilter("/*")
public class AuthenticationFilter extends HttpFilter {

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {

        String path = req.getRequestURI().substring(req.getContextPath().length());

        // If path starts with /login, /register or /static, permit access
        // without authentication.
        boolean authenticationRequired = true;
        if (path.matches("^/(generate|login|register|static|ArquillianServletRunner).*")) {
            authenticationRequired = false;
        }
        else {
            // User will be required to authenticate but we want to remember the
            // original path he tried to access, will be used in the login servlet.
            req.setAttribute("targetUrl", path);
        }

        String username = (String) req.getSession().getAttribute("username");
        if (authenticationRequired && username == null) {
            // User is not logged in, redirect to login page.
            res.sendRedirect("/project-one/login");
        }
        else {
            // User is logged in or authentication is not required,
            // the request can continue as normal.
            chain.doFilter(req, res);
        }
    }
}
