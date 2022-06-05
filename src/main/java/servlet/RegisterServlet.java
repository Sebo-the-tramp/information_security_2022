package servlet;

import jakarta.servlet.http.HttpServlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import utils.RSAKeyPair;
import utils.RSAConstants;
import utils.RSAEncryptDecrypt;

/**
 * Servlet implementation class RegisterServlet
 */
@WebServlet("/RegisterServlet")
public class RegisterServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	private static final String USER = "root";
	private static final String PWD = "MyN3wP4ssw0rd";
	private static final String DRIVER_CLASS = "org.mariadb.jdbc.Driver";
	private static final String DB_URL = "jdbc:mariadb://localhost:3306/examDB?encrypt=true;trustServerCertificate=true;";
    
	private static Connection conn;
	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public RegisterServlet() {
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
		
		// The replacement escapes apostrophe special character in order to store it in SQL
		String name = request.getParameter("name").replace("'", "''");
		String surname = request.getParameter("surname").replace("'", "''");;
		String email = request.getParameter("email").replace("'", "''");;
		String pwd = request.getParameter("password").replace("'", "''");;
				
		//if(!name.matches("[\\w*\\s*]*") || !surname.matches("[\\w*\\s*]*")) {
		if(true) {
			System.out.println("ha");
			
			try (Statement st = conn.createStatement()) {
				ResultSet sqlRes = st.executeQuery(
					"SELECT * "
					+ "FROM user "
					+ "WHERE email='" + email + "'"
				);
				
				if (sqlRes.next()) {
					System.out.println("Email already registered!");
					request.getRequestDispatcher("register.html").forward(request, response);
					
				} else {
					
					response.setContentType("text/plain");
			        response.setHeader("Content-disposition", "attachment; filename=private_key_"+ email +".txt");
					
					String salt = getSalt();
					String hashedPassword = getSecurePassword(pwd, salt);
					
					//CREATE KEY PAIR					
					KeyPair keyPair = RSAKeyPair.keyPairRSA();
					Key publicKey = keyPair.getPublic();
					Key privateKey = keyPair.getPrivate();
					
					// DOWNLOAD PRIVATE KEY			 
					
					try(InputStream in = new ByteArrayInputStream(("PRIVATE KEY: " + toHex(privateKey.getEncoded())).getBytes());
				          OutputStream out = response.getOutputStream()) {

				            byte[] buffer = new byte[1024];
				        
				            int numBytesRead;
				            while ((numBytesRead = in.read(buffer)) > 0) {
				                out.write(buffer, 0, numBytesRead);
			            }
			        }					       
					
					st.execute(
						"INSERT INTO user ( name, surname, email, password, public_key ) "
						+ "VALUES ( '" + name + "', '" + surname + "', '" + email + "', '" + hashedPassword + "', '" + toHex(publicKey.getEncoded()) + "' )"
					);
					
					request.setAttribute("email", email);
					request.setAttribute("password", pwd);
					
					System.out.println("Registration succeeded!");																
					
					//request.getRequestDispatcher("home.jsp").forward(request, response);
				}
				
			} catch (SQLException e) {
				e.printStackTrace();
				request.getRequestDispatcher("register.html").forward(request, response);
			}
		}
	}	
	
    private static String getSecurePassword(String passwordToHash,
            String salt) {
        String generatedPassword = null;
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // Add password bytes to digest
            md.update(salt.getBytes());                       
            
            // Get the hash's bytes
            byte[] bytes = md.digest(passwordToHash.getBytes());
            
            // This bytes[] has bytes in decimal format;
            // Convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            
            for (int i = 0; i < salt.getBytes().length; i++) {
            	sb.append(Integer.toString((salt.getBytes()[i] & 0xff) + 0x100, 16)
                        .substring(1));
            }
            
            sb.append(':');
            
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
                        .substring(1));
            }
            
            // Get complete hashed password in hex format
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    // Add salt
    private static String getSalt()            
    {           
    	SecureRandom random = new SecureRandom();
    	
        // Create array for salt
        byte[] salt = new byte[16];

        // Get a random salt
        random.nextBytes(salt);

        // return salt
        return salt.toString();
    }
    
    private String toHex(byte[] word) {
    	
    	StringBuilder sb = new StringBuilder();
    	
    	for (int i = 0; i < word.length; i++) {
        	sb.append(Integer.toString((word[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
    	
    	return sb.toString();
    }

}
