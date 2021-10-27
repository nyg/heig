<%@include file="includes/header.jsp" %>
<!-- Page Content -->
<div class="container">

    <div class="row">
        <!-- /.col-lg-3 -->
        <!-- Carousel -->
        <div id="carouselExampleIndicators" class="carousel slide my-4" data-ride="carousel">
            <ol class="carousel-indicators">
                <li data-target="#carouselExampleIndicators" data-slide-to="0" class="active"></li>
                <li data-target="#carouselExampleIndicators" data-slide-to="1"></li>
                <li data-target="#carouselExampleIndicators" data-slide-to="2"></li>
            </ol>
            <div class="carousel-inner" role="listbox">
                <div class="carousel-item active">
                    <img class="d-block img-fluid" src="http://placehold.it/1200x350" alt="First slide">
                </div>
                <div class="carousel-item">
                    <img class="d-block img-fluid" src="http://placehold.it/1200x350" alt="Second slide">
                </div>
                <div class="carousel-item">
                    <img class="d-block img-fluid" src="http://placehold.it/1200x350" alt="Third slide">
                </div>
            </div>
            <a class="carousel-control-prev" href="#carouselExampleIndicators" role="button" data-slide="prev">
                <span class="carousel-control-prev-icon" aria-hidden="true"></span>
                <span class="sr-only">Previous</span>
            </a>
            <a class="carousel-control-next" href="#carouselExampleIndicators" role="button" data-slide="next">
                <span class="carousel-control-next-icon" aria-hidden="true"></span>
                <span class="sr-only">Next</span>
            </a>
        </div>

        <!-- articles -->
        <div class="row">
            <c:forEach items="${articles}" var="article">
                <div class="col-lg-4 col-md-6 mb-4">
                    <div class="card h-100">
                        <a href="#"><img class="card-img-top" src="http://placehold.it/700x400" alt=""></a>
                        <div class="card-body">
                            <h4 class="card-title">
                                <p>${article.name}</p>
                            </h4>
                            <h5>${article.price} $</h5>
                            <p class="card-text">${article.description}</p>
                            <a href="./cart?&action=buy&id=${article.id}">Add to cart</a>
                        </div>
                    </div>
                </div>
            </c:forEach>
        </div>
        <!-- /.row -->
    </div>
    <!-- /.row -->
    <div class="push">
    </div>
    <div class ="paginationCenter">
        <div class="pagination">
            <c:set var="previousPage" value = "${pageNumber - 1}"></c:set>
            <c:set var="nextPage" value = "${pageNumber + 1}"></c:set>
            <c:set var="minPage" value = "${pageNumber - 3}"></c:set>
            <c:set var="maxPage" value = "${pageNumber + 3}"></c:set>
            <c:if test="${maxPage gt pageCount}">
                <c:set var="maxPage" value ="${pageCount}"></c:set>
            </c:if>
            <c:if test="${nextPage gt pageCount}">
                <c:set var="nextPage" value ="${pageCount}"></c:set>
            </c:if>
            <c:if test="${pageNumber lt 4}">
                <c:set var="minPage" value ="1"></c:set>
            </c:if>
            <c:if test="${previousPage lt 1}">
                <c:set var="previousPage" value ="1"></c:set>
            </c:if>

            <a class="pagination" href="./articles?pageNumber=1">&laquo;</a>
            <a class="pagination" href="./articles?pageNumber=${previousPage}">&LT;</a>
            <c:forEach var="i" begin="${minPage}" end="${maxPage}">
                <c:choose>
                    <c:when test="${pageNumber == i}">
                        <a class="pagination active" href="./articles?pageNumber=${i}">${i}</a>
                    </c:when>
                    <c:otherwise>
                        <a class="pagination" href="./articles?pageNumber=${i}">${i}</a>
                    </c:otherwise>
                </c:choose>
            </c:forEach>
            <a class="pagination" href="./articles?pageNumber=${nextPage}">&GT;</a>
            <a class="pagination" href="./articles?pageNumber=${pageCount}">&raquo;</a>
        </div>
    </div>
    <div class="push2"></div>
</div>

<%@include file="includes/footer.jsp" %>
