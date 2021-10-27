package ch.heigvd.amt.projectone.app;

import ch.heigvd.amt.projectone.service.GenerationServiceLocal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GenerateServletTest {

    private static final int ENTRY_COUNT = 10;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    RequestDispatcher requestDispatcher;

    @Mock
    GenerationServiceLocal generationService;

    private GenerateServlet servlet;

    @BeforeEach
    void setup() {

        // set up servlet
        servlet = new GenerateServlet();
        servlet.generationService = generationService;

        // set up request
        when(request.getRequestDispatcher(GenerateServlet.JSP)).thenReturn(requestDispatcher);
    }

    @Test
    void doPostShouldCallGenerateMethodOfService() throws ServletException, IOException {

        when(request.getParameter("entry-count")).thenReturn(String.valueOf(ENTRY_COUNT));

        servlet.doPost(request, response);

        verify(generationService).generate(ENTRY_COUNT);
        verify(request).setAttribute(eq("result"),  any());

        verify(request).getRequestDispatcher(GenerateServlet.JSP);
        verify(requestDispatcher).forward(request, response);
    }

    @Test
    void doGetShouldForwardRequest() throws ServletException, IOException {

        servlet.doGet(request, response);

        verify(request).getRequestDispatcher(GenerateServlet.JSP);
        verify(requestDispatcher).forward(request, response);
    }
}