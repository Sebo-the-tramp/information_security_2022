package servlet;

import jakarta.servlet.http.HttpServlet;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class HelloWorldServlet
 */
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	private static final String USER = "root";
	private static final String PWD = "MyN3wP4ssw0rd";
	private static final String DRIVER_CLASS = "org.mariadb.jdbc.Driver";
	private static final String DB_URL = "jdbc:mariadb://localhost:3306/examDB?encrypt=true;trustServerCertificate=true;";
    
	private static Connection conn;
	
	/**
     * @see HttpServlet#HttpServlet()
     */
    public LoginServlet() {
        super();
    }
    
    public void init() throws ServletException {
    	try {
			Class.forName(DRIVER_CLASS);
			
		    Properties connectionProps = new Properties();
		    connectionProps.put("user", USER);
		    connectionProps.put("password", PWD);
	
	        conn = DriverManager.getConnection(DB_URL, connectionProps);
		    
		    //System.out.println("User \"" + USER + "\" connected to database.");
    	
    	} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
    }

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String email = request.getParameter("email");
		String pwd = request.getParameter("password");

		String sql_query = "SELECT * "
				+ "FROM user "
				+ "WHERE email = ?";
		
		try (PreparedStatement st = conn.prepareStatement(sql_query)) {
			
			st.setString(1, email);
			
			ResultSet sqlRes = st.executeQuery();
			
			sqlRes.next();
			String complete = "";
			String password = sqlRes.getString(4);
			String saltString = password.split(":")[0];
						
			System.out.println(pwd);
			
			MessageDigest md;
			try {
				md = MessageDigest.getInstance("SHA-256");
				md.update(fromHex(saltString));
				byte[] hashedPassword = md.digest(pwd.getBytes());
				
				StringBuilder sb = new StringBuilder();	            	           
	            
	            for (int i = 0; i < hashedPassword.length; i++) {
	                sb.append(Integer.toString((hashedPassword[i] & 0xff) + 0x100, 16)
	                        .substring(1));
	            }
	            
	            String hashString = sb.toString();
				
				complete = saltString + ":" + hashString;
										
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			System.out.println("new:    " + complete + "\nstored: " + password);
			System.out.println(password.compareTo(saltString));
			
			if (password.compareTo(complete) == 0) {
				request.setAttribute("email", sqlRes.getString(3));
				request.setAttribute("password", sqlRes.getString(4));				
				
				System.out.println("Login succeeded!");
				request.setAttribute("content", "");
				request.getRequestDispatcher("home.jsp").forward(request, response);
				
				
			} else {
				System.out.println("Login failed!");
				request.getRequestDispatcher("login.html").forward(request, response);
			}
			
		} catch (SQLException e) {			
			e.printStackTrace();
			request.getRequestDispatcher("login.html").forward(request, response);
		}
	}
	
	private byte[] fromHex(String word) {
		
		byte[] binary = new byte[word.length()/2];
		for(int i = 0; i < binary.length; i++) {
			binary[i] = (byte) Integer.parseInt(word.substring(2*i, 2*i +2), 16);
		}
		return binary;
	}
}
