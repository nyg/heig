import Web.{MessagesRoutes, StaticRoutes, StatisticsRoutes, UsersRoutes}

object Main extends cask.Main {
  val allRoutes = Seq(StaticRoutes(), UsersRoutes(), MessagesRoutes(), StatisticsRoutes())
}
