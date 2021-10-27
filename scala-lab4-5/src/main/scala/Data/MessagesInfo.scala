package Data

import Data.DatabaseContext.ctx._
import Data.DatabaseContext.{Message, ctx}

object MessagesInfo {

  // Step 4a - TODO: Store the messages and the corresponding user in memory.
  //       Implement methods to add new messages and to get the last 20 messages.

  def addMessage(username: String,
                 content: String,
                 replyTo: Option[Long] = Option.empty,
                 mention: Option[Long] = Option.empty,
                 exprTypeId: Option[Long] = Option.empty): Option[Long] =
    UsersInfo getAccountId username map { userId =>
      ctx.run(query[Message].insert(
        _.userId -> lift(userId),
        _.content -> lift(content),
        _.replyToId -> lift(replyTo),
        _.mentionId -> lift(mention),
        _.exprTypeId -> lift(exprTypeId))
        .returning(_.messageId))
    }

  def getLastTwenty: List[Message] =
    ctx.run(query[Message].sortBy(_.createdDate)(Ord.desc).take(20)).reverse

  def clearHistory(): Unit =
    ctx.run(query[Message].delete)
}
