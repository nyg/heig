package Web

import Data.UsersInfo
import cask.model.Response
import cask.model.Response.Raw
import scalatags.Text
import scalatags.Text.all.html


/**
  * Assembles the routes dealing with the users:
  * - One route to display the login form page
  * - One route to process the login form and display the login success page
  * - One route to display the register form page
  * - One route to process the register form and display the register success page
  * - One route to logout and display the logout success page
  *
  * The username of the current session user is stored inside a cookie called `username`.
  */
case class UsersRoutes()(implicit val log: cask.Logger) extends cask.Routes {

  // Step 3a - Display a login form and register form page for the following
  //           URL: `/login`.
  @cask.get("/login")
  def login(): Text.TypedTag[String] =
    Layouts.login()


  // Step 3b - Process the login information sent by the form with POST to
  //           `/login`, create a user session using a cookie (if the user
  //           exists) and display a successful or failed login page.
  @cask.postForm("/login")
  def postLogin(username: String): Response[Text.TypedTag[String]] = username match {
    case u if UsersInfo doesAccountExist u =>
      cask.Response(
        Layouts.success(Option(username), "Login successful 😘"),
        cookies = Seq(cask.Cookie("username", username)))
    case _ =>
      cask.Response(Layouts.login("Login failed 😰 Try registering first 😉"))
  }


  // Step 3c - Process the register information sent by the form with POST to
  //           `/register`, create the user, create a user session using a
  //           cookie and display a successful register page.
  @cask.postForm("/register")
  def postRegister(username: String): Response[Text.TypedTag[String]] = username match {
    case u if u.isBlank || u.exists(!_.isLetter) =>
      cask.Response(Layouts.login(registerError = "Registration failed 😰 Try using some letters 😉"))
    case u if UsersInfo.doesAccountExist(u) =>
      cask.Response(Layouts.login(registerError = "Registration failed 😰 Maybe this username is already taken 🤫️"))
    case u =>
      UsersInfo.addAccount(u, 30)
      cask.Response(
        Layouts.success(Option(username), "Registration successful 😉"),
        cookies = Seq(cask.Cookie("username", username)))
  }


  // Step 3d - Destroy the current session and display a successful logout page.
  @cask.get("/logout")
  def logout() =
    cask.Response(
      Layouts.success(Option.empty, "Logout successful 😭"),
      cookies = Seq(cask.Cookie("username", "", expires = java.time.Instant.EPOCH)))


  initialize()
}
