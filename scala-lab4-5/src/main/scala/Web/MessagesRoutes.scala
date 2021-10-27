package Web

import Chat.{Parser, Tokenizer}
import Data.{MessagesInfo, UsersInfo}
import cask.endpoints.WsChannelActor
import cask.model.Response
import scalatags.Text
import ujson.Obj

import scala.collection.mutable


/**
  * Assembles the routes dealing with the message board:
  * - One route to display the home page
  * - One route to send the new messages as JSON
  * - One route to subscribe with websocket to new messages
  *
  * @param log
  */
case class MessagesRoutes()(implicit val log: cask.Logger) extends cask.Routes {

  import Decorators.loggedIn

  // This decorator fills the `(user: Option[String])` part of the `index`
  // method with the user who requests the page.
  @loggedIn
  @cask.get("/")
  def index()(user: Option[String]): Text.TypedTag[String] =
    Layouts.index(user)

  @cask.get("/clearHistory")
  def clearHistory(): Response[Text.TypedTag[String]] = {
    MessagesInfo.clearHistory()
    cask.Response(Layouts.success(Option.empty, "History cleared 🤯"))
  }

  // Step 4c - Store the current websocket connections
  val channels: mutable.Set[WsChannelActor] = mutable.HashSet()

  // Step 4b - Process the new messages sent as JSON object to `/send`. The JSON looks
  //       like this: `{ "msg" : "The content of the message" }`.
  //
  //       A JSON object is returned. If an error occured, it looks like this:
  //       `{ "success" : false, "err" : "An error message that will be displayed" }`.
  //       Otherwise (no error), it looks like this:
  //       `{ "success" : true, "err" : "" }`
  //
  //       The following are treated as error:
  //       - No user is logged in
  //       - The message is empty
  //
  //       If no error occured, every other user is notified with the last 20 messages
  //
  @loggedIn
  @cask.postJson("/send")
  def send(msg: ujson.Str)(user: Option[String]): Obj = {

    def notifyUsers(): Obj = {
      // for each active channel send the last 20 messages
      channels.foreach(_.send(cask.Ws.Text(messages())))
      ujson.Obj("success" -> true, "err" -> "")
    }

    (user, msg.value) match {
      case (u, _) if u.isEmpty => ujson.Obj("success" -> false, "err" -> "Not logged in")
      case (_, m) if m.isEmpty => ujson.Obj("success" -> false, "err" -> "Empty message")
      case (_, m) if m.startsWith("@") =>
        val pattern = "@(.*?) (.*?)".r
        val pattern(mentionedUsername, messageOnly) = msg.value

        if (mentionedUsername == "bot") {

          // log in the active user
          UsersInfo.setActiveUser(user.get)

          val t = new Tokenizer(messageOnly)
          t.tokenize()

          try {
            val r = new Parser(t).parsePhrases()
            val msgId = MessagesInfo.addMessage(user.get, msg.value, mention = UsersInfo.getAccountId("BotTender"))
            MessagesInfo.addMessage("BotTender", r.reply, replyTo = msgId, exprTypeId = Option(r.exprTypeId))
          } catch {
            case e: Exception =>
              return ujson.Obj("success" -> false, "err" -> s"Je n'ai pas très bien compris, ${e.getMessage.replace("Fatal error: ", "")}")
          }
        } else MessagesInfo.addMessage(user.get, msg.value, mention = UsersInfo.getAccountId(mentionedUsername))

        notifyUsers()

      case _ =>
        MessagesInfo.addMessage(user.get, msg.value)
        notifyUsers()
    }
  }

  // Step 4c - Process the new websocket connection made to `/subscribe`.
  @cask.websocket("/subscribe")
  def subscribe(): cask.WebsocketResult =
    cask.WsHandler { channel =>

      // add channel to our list
      channels += channel

      // send already existing message when user connects
      if (MessagesInfo.getLastTwenty.nonEmpty)
        channel.send(cask.Ws.Text(messages()))

      cask.WsActor {
        // if client closes the channel, we remove it from our list
        case cask.Ws.ChannelClosed() => channels -= channel
      }
    }

  private def messages() =
    MessagesInfo.getLastTwenty.map(m => Layouts.message(UsersInfo.getUsername(m.userId).get, m.content)).mkString

  initialize()
}
