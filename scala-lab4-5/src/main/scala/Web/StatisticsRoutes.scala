package Web

import scalatags.Text.all._
import scalatags.Text.{tags2}
import scala.util.{Try, Success, Failure}

import Data.{StatisticsInfo => Stats}
import java.time.Duration
import Data.UsersInfo
import scalatags.stylesheet._

/**
  * Assembles the route, layouts and methods dealing with the statistics.
  */
case class StatisticsRoutes()(implicit val log: cask.Logger) extends cask.Routes {
    import Decorators.loggedIn

    @loggedIn
    @cask.get("/statistics")
    def statisticsEntrypoint()(user: Option[String]) = {
      val userId = user.flatMap(u => UsersInfo.getAccountId(u))
      doctype("html")(
        html(
          head(
            tags2.title("Bot-tender Statis"),
            // Labo 5 TODO: Link to the main CSS file.
            link(rel := "stylesheet", `type` := "text/css", href := ""),
            tags2.style(StatisticsStyle.styleSheetText)),
          body(
            tags2.nav(
                a(`class` := "nav-brand")("Bot-tender Stats"),
                user.map(u =>
                    frag(div(`class`:="nav-item")(s"Hello ${u} !"), div(`class`:="nav-item")(a(href:="/logout")("Log out")))
                ).getOrElse(
                    frag(div(`class`:="nav-item")(a(href:="/login")("Log in")))
                )
            ),
            div(cls:="content")(
              ul(StatisticsStyle.cards)(
                userId.map( uid =>
                  frag(
                    statisticCard(Stats.nbMessages(uid))("Number of messages you sent")
                  )
                ).getOrElse(
                  frag(
                    statisticCardLayout("Personnal statistics", "You must be logged to see them")
                  )
                ),
                statisticCard(Stats.nbMessages)("Number of messages sent"),
                statisticCard(Stats.topSender)("Top sender", _ match {
                  case Some((username, nbMsg)) => annotatedLayout(username, s"with a total of ${nbMsg} messages")
                  case None => valueLayout("No one yet")
                }),
                statisticCard(Stats.topMentionPair)("Top mentioning pair of users", _ match {
                  case Some((username1, username2, nb)) => annotatedLayout(s"$username1 -> $username2", s"with a total of ${nb} mentions")
                  case None => valueLayout("Not enough mentions yet")
                }),
                statisticCard(Stats.topThirstyOrHungry)("Most thirsty and hungry user", _ match {
                  case Some((username, nbMsg)) => annotatedLayout(username, s"with ${nbMsg} messages about his hunger and thirst")
                  case None => valueLayout("No one yet")
                }),
                statisticCard(Stats.hourMostMsgs)("Busiest period", _ match {
                  case Some((hour, nbMsg)) => {
                    val hourEnd = (hour + 1).toString()
                    annotatedLayout(s"Between ${hour}h and ${hourEnd}h", s"with a total of ${nbMsg} messages sent")
                  }
                  case None => valueLayout("No message yet")
                }),
                statisticCard(Stats.topPoorestNoCommands)("Poorest user who hasn't commanded anything", _ match {
                  case Some(username) => valueLayout(username)
                  case None => valueLayout("No one yet")
                })
              )
            )
          )
        )
      )
    }

    def valueLayout(value: Frag): Frag =
      div(StatisticsStyle.value)(value)

    def annotatedLayout(main: Frag, annotation: Frag): Frag =
      div(
        valueLayout(main),
        div(fontSize.small, textAlign.center)(annotation)
      )

    def statisticCardLayout(title: Frag, text: Frag, err: Option[Frag] = None): Frag =
      li(StatisticsStyle.cardsItem)(
        div(StatisticsStyle.card)(
          err.map(e => frag(div(StatisticsStyle.cardError)(e))).getOrElse(frag()),
          header(StatisticsStyle.cardTitle)(title),
          div(StatisticsStyle.cardText)(text)
        )
      )

    def statisticCard[T](f: => T)(title: Frag, displayer: T => Frag = (x: T) => valueLayout(x.toString)) = {
        val (value, err) = Try{f} match {
          case Success(v) => (displayer(v), None)
          case Failure(exception) => (valueLayout("???"), Some(frag(exception.toString())))
        }

        statisticCardLayout(title, value, err)
    }

    initialize()
}

/**
  * Assembles the styling of the statistics page
  */
object StatisticsStyle extends StyleSheet {
  initStyleSheet()

  val cards = cls(
    display.flex,
    flexWrap.wrap,
    listStyle:="none",
    margin:=0,
    marginTop:="1rem",
    padding:=0
  )

  val cardsItem = cls(
    display.flex,
    padding:="0.25rem",
    width:="50%",
    boxSizing.`border-box`
  )

  val card = cls(
    borderRadius:="0.25rem",
    border:="solid #aaa 1px",
    display.flex,
    flexGrow:="1",
    flexDirection.column,
    overflow.hidden,
    position.relative
  )

  val cardError = cls(
    position.absolute,
    top:="0",
    right:="0",
    padding:="1rem",
    backgroundColor:="#e40303",
    boxSizing.`border-box`,
    color:="rgba(0,0,0,0)",
    width:="0",
    height:="0",
    overflow.hidden,
    borderBottomLeftRadius:="100%",
    &.hover(
      color:="white",
      width:="100%",
      height:="auto",
      maxHeight:="100%",
      overflowY.auto,
      borderBottomLeftRadius:="2rem"
    )
  )

  val cardTitle = cls(
    fontWeight:="300",
    fontSize:="1.25rem",
    backgroundColor:="#fafafa",
    padding:="1rem"
  )

  val cardText = cls(
    flex:="1 1 auto",
    padding:="1rem",
    display.flex,
    alignItems.center,
    justifyContent.center,
    flexDirection.column
  )

  val value = cls(
    textAlign.center,
    fontWeight.bold
  )
}
