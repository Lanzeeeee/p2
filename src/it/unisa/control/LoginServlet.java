package it.unisa.control;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import it.unisa.model.*;

/**
 * Servlet implementation class LoginServlet
 */
@WebServlet("/Login")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}
			
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
	UserDao usDao = new UserDao();
		
		try
		{	    
			
			 String username = request.getParameter("un");
	            String password = request.getParameter("pw");
	            
	            // Codifica la password in SHA-512
	            String encodedPassword = encodeSHA512(password);
	            UserDao userDao = new UserDao();
	            
	            UserBean user = userDao.doRetrieve(username, encodedPassword);

	            String checkout = request.getParameter("checkout");
	            
		     if (user.isValid())
		     {
			        
		          HttpSession session = request.getSession(true);	    
		          session.setAttribute("currentSessionUser",user); 
		          if(checkout!=null)
		        	  response.sendRedirect(request.getContextPath() + "/account?page=Checkout.jsp");
		          
		          else
		        	  response.sendRedirect(request.getContextPath() + "/Home.jsp");
		     }
			        
		     else 
		          response.sendRedirect(request.getContextPath() +"/Login.jsp?action=error"); //error page 
		} 
				
				
		catch(SQLException e) {
			System.out.println("Error:" + e.getMessage());
		}
		  }
	
	private String encodeSHA512(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(password.getBytes());
            
            // Converti il byte array in una rappresentazione esadecimale
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }
            
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
	}
