<%@include file="includes/header.jsp" %>
<div class="container">
    <div class="row">
        <div class="col-lg-3">
            <br>
            <h3>AMT Shop - Register</h3>
        </div>
        <div class="col-lg-9">
            <div class="col-md-6 login-form-1">

                <c:if test="${success != null}">
                    <div>
                        <div>
                            <h4 class="card-title">
                                <p>Your account was successfully created !</p>
                            </h4>
                        </div>
                    </div>
                </c:if>

                <form action="register" method="post">

                    <div class="form-group">
                        <label for="firstname">Firstname</label>
                        <input id="firstname" type="text" class="form-control" name="firstname" value="" required>
                    </div>
                    <div class="form-group">
                        <label for="lastname">Lastname</label>
                        <input id="lastname" type="text" class="form-control" name="lastname" value="" required>
                    </div>
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input id="username" type="text" class="form-control" name="username" value="" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input id="email" type="text" class="form-control" name="email" value="" required>
                    </div>
                    <div class="form-group">
                        <label for="pw">Password</label>
                        <input id="pw" type="password" class="form-control" name="password"value="" required>
                    </div>
                    <div class="form-group">
                        <input type="submit" class="btnSubmit" value="Register">
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class ="push"></div>
</div>
<%@include file="includes/footer.jsp" %>
