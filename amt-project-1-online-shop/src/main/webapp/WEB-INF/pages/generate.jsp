<%@include file="includes/header.jsp" %>

<div class="container basic-container">
    <div class="col-md-6 basic-form-1">

        <h4>Generate</h4>

        <c:if test="${result != null}">
            <p><c:out value="${result}"/></p>
        </c:if>

        <form action="generate" method="post">
            <div class="form-group">
                <label for="entry-count">Entry count</label>
                <input type="text" name="entry-count" id="entry-count" value="1000">
            </div>
            <div class="form-group">
                <input type="submit" value="Generate">
            </div>
        </form>
    </div>
</div>

<%@include file="includes/footer.jsp" %>
