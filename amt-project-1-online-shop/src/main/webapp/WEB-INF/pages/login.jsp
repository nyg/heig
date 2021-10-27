<%@include file="includes/header.jsp" %>
<div class="container">
    <div class="row">
        <div class="col-lg-3">
            <br>
            <h3>AMT Shop - Login</h3>
        </div>
        <div class="col-lg-9">
            <div class="col-md-6 login-form-1">

                <form action="login" method="post">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input id="username" type="text" class="form-control" name="username" value="" >
                    </div>
                    <div class="form-group">
                        <label for="pw">Password</label>
                        <input id="pw" type="password" class="form-control" name="password" value="">
                    </div>
                    <div class="form-group">
                        <input type="submit" class="btnSubmit" value="Login">
                    </div>
                </form>
                <div class="form-group">
                    <a href="./register" class="signIn">Not register yet ?</a>
                </div>
            </div>
        </div>
    </div>
    <div class ="push"></div>
</div>
<%@include file="includes/footer.jsp" %>
