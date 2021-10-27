<%@include file="includes/header.jsp"%>

<div class="container">
    <div class="row">
        <c:choose>
        <c:when test="${not empty articles}">
            <c:forEach items="${articles}" var="article">
                <div class="col-lg-4 col-md-6 mb-4">
                    <div class="card-body">
                        <h4 class="card-title">
                            <p>${article.name}</p>
                        </h4>
                        <h5>${article.price} $</h5>
                        <p class="card-text">${article.description}</p>
                    </div>
                </div>
            </c:forEach>
            <div class="col-lg-4 col-md-6 mb-4">
                <div class="card-body">
                    <h4 class="card-title">
                        <a href="./cart?action=deleteAll">Clear cart</a>
                    </h4>
                </div>
            </div>
        </c:when>
        <c:otherwise>
            <div class="col-lg-4">
                <div class="card-body">
                    <h4 class="card-title">
                        <p>Your cart is empty.</p>
                    </h4>
                </div>
            </div>
        </c:otherwise>
        </c:choose>
    </div>
</div>

<%@include file="includes/footer.jsp"%>