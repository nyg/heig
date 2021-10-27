package Web

/**
  * Assembles the routes dealing with static files.
  */
case class StaticRoutes()(implicit val log: cask.Logger) extends cask.Routes {

  @cask.staticResources("/static/resource")
  def staticResourcesRoutes() = ""

  initialize()
}
