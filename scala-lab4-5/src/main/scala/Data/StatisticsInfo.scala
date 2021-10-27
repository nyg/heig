package Data

import java.time.LocalDateTime

import Data.DatabaseContext.ctx._
import Data.DatabaseContext.{Account, Message, ctx}

object StatisticsInfo {

  // Labo 5 Get the number of messages sent.
  def nbMessages: Long =
    ctx.run(query[Message].size)

  // Labo 5 Get the number of message sent by the given user.
  def nbMessages(userId: Long): Long =
    ctx.run(query[Message].filter(_.userId == lift(userId)).size)

  // Labo 5 Get the name of the user having sent the most messages. Also get the number of message he sent.
  def topSender: Option[(String, Long)] =
    ctx.run(query[Message]
      .join(query[Account])
      .on(_.userId == _.userId)
      //      .groupBy(_._1.userId)
      //      .map(r => (r._2.map(_._2.username), r._2.size))
      .groupBy(_._2.username)
      .map(r => (r._1, r._2.map(_._1).size))
      .sortBy(_._2)(Ord.desc)
    ).headOption

  // Labo 5 Get, if he exists, the name of the user having told the bot that he was hungry or thirsty the
  //              most. Also get the number of times.
  def topThirstyOrHungry: Option[(String, Long)] =
    ctx.run(query[Message]
      .filter(m => m.exprTypeId.contains(5L) || m.exprTypeId.contains(6L))
      .join(query[Message])
      .on((m1, m2) => m1.replyToId.contains(m2.messageId))
      .join(query[Account])
      .on((m, a) => m._2.userId == a.userId)
      .groupBy(_._2.username)
      .map(r => (r._1, r._2.map(_._1._1).size))
    ).headOption

  // Labo 5 Get, if he exists, the name of the poorest user who has never commanded something from the Bot.
  def topPoorestNoCommands: Option[String] = {

    // list des userIds qui ont commandé au moins une chose auprès du bot
    val ids: List[Long] = ctx.run(
      query[Message]
        .filter(m => m.exprTypeId.contains(3L))
        .join(query[Message])
        .on((m1, m2) => m1.replyToId.contains(m2.messageId))
        .join(query[Account])
        .on((m, a) => m._2.userId == a.userId)
        .map(_._2.userId))

    ctx.run(query[Account]
      .filter(_.username != "BotTender")
      .filter(u => !lift(ids).contains(u.userId))
      .sortBy(_.balance)(Ord.asc)
      .map(_.username)
    ).headOption
  }

  // Labo 5 TODO: Get the hour of the day which had the most messages sent. Also get the number of messages.
  //              (e.g. a message sent Monday 3h23 and another sent Tuesday 3h54 both count for the total of
  //              message sent at 3h)
  def hourMostMsgs: Option[(Int, Long)] = {

    val getHour = quote {
      (d: LocalDateTime) => infix"extract(hour from $d)".as[Int]
    }

    ctx.run(query[Message]
      .groupBy(r => getHour(r.createdDate))
      .map(r => (r._1, r._2.size))
      .sortBy(_._2)(Ord.desc)
    ).headOption
  }

  // Labo 5 TODO: Get, if there exists mentions, the names of the pair of users whos first user has most
  //              mentionned the second. Also get the number of mentions
  def topMentionPair: Option[(String, String, Long)] =
    ctx.run(query[Message]
      .join(query[Account])
      .on((m, a) => m.userId == a.userId)
      .join(query[Account])
      .on((m, a) => m._1.mentionId.contains(a.userId))
      .filter(u => u._2.username != "BotTender")
      .groupBy(r => (r._1._2.username, r._2.username))
      .map(r => (r._1._1, r._1._2, r._2.map(_._1._1).size))
      .sortBy(_._3)(Ord.desc)
    ).headOption
}
