package Web

import scalatags.Text
import scalatags.Text.all._
import scalatags.Text.tags2.nav


/**
  * Assembles the method used to layout ScalaTags
  */
object Layouts {

  /**
    * Provides the basic layout for an empty page.
    */
  def main(navItem: Text.TypedTag[String], includeJs: Boolean = false)(content: Modifier*): Text.TypedTag[String] =
    html(lang := "en")(
      head(
        meta(charset := "utf-8"),
        if (includeJs) script(`type` := "text/javascript", src := "static/resource/js/main.js") else (),
        link(rel := "stylesheet", `type` := "text/css", href := "static/resource/css/main.css")),
      body(
        nav(
          a(`class` := "nav-brand", href := "/")("Bot-tender"),
          div(`class` := "nav-item")(navItem)),
        div(`class` := "content")(
          List(content))))

  /**
    * Based on the main layout, but includes the nav-item indicating the user is logged in or not.
    */
  def mainUser(user: Option[String], includeJs: Boolean = false): Seq[Text.all.Modifier] => Text.TypedTag[String] =
    main(user
      .map(u => p("You are logged in as ", strong(u), " — ", a(href := "/logout")("Logout")))
      .getOrElse(p(a(href := "/login")("Login"))),
      includeJs)

  /**
    * Info page layout with either a success of error message.
    */
  def success(user: Option[String], message: String): Text.TypedTag[String] =
    mainUser(user)(Seq(
      div(`class` := "successMsg")(message)))

  /**
    * The index "/" page layout.
    */
  def index(user: Option[String]): Text.TypedTag[String] =
    mainUser(user, includeJs = true)(Seq(
      div(id := "boardMessage")(
        p("Please wait, the messages are loading!")),
      form(id := "msgForm", onsubmit := "submitMessageForm(); return false")(
        div(id := "errorDiv", `class` := "errorMsg"),
        label(`for` := "messageInput")("Your message"),
        input(id := "messageInput", `type` := "text", placeholder := "Write your message"),
        input(`type` := "submit", value := "Send"))))

  def message(author: String, content: String): Text.TypedTag[String] =
    div(`class` := "msg")(
      span(`class` := "author")(author),
      span(`class` := "msg-content")(content)
    )

  /**
    * The login/register page layout.
    */
  def login(loginError: String = "", registerError: String = ""): Text.TypedTag[String] =
    main(
      a(href := "/")("Go to the message board")
    )(
      h2("Login"),
      buildForm("loginForm", "login", loginError, "username"),
      h2("Register"),
      buildForm("registerForm", "register", registerError, "username"))

  private def buildForm(fId: String, fAction: String = "", error: String = "", inputName: String): Text.TypedTag[String] =
    form(id := fId, method := "post", action := fAction)(
      div(id := "errorDiv", `class` := "errorMsg")(error),
      label(`for` := s"$fId-$inputName")(inputName.capitalize),
      input(id := s"$fId-$inputName", `type` := "text", name := inputName, placeholder := inputName.capitalize),
      input(`type` := "submit", value := "Send"))
}
