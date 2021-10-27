package Data

import Data.DatabaseContext.ctx._
import Data.DatabaseContext.{Account, ctx}

// TODO: Adapt UsersInfo to use the database.
object UsersInfo {

  private var _activeUser: String = _
  def getActiveUser: String = _activeUser
  def setActiveUser(user: String): Unit = _activeUser = user

  def getAccountBalance(user: String): Double =
    ctx.run(query[Account].filter(_.username == lift(user)).map(_.balance)).head

  def addAccount(user: String, balance: Double): Unit =
    ctx.run(query[Account].insert(_.username -> lift(user), _.balance -> lift(balance), _.active -> true))

  def doesAccountExist(user: String): Boolean =
    ctx.run(query[Account].filter(_.username == lift(user))).nonEmpty

  // Labo 5 TODO: Implement a method to get the id of an account based on its username.
  def getAccountId(user: String): Option[Long] =
    ctx.run(query[Account].filter(_.username == lift(user)).map(_.userId)) match {
      case Nil => Option.empty
      case x :: _ => Option(x)
    }

  def getUsername(id: Long): Option[String] =
    ctx.run(query[Account].filter(_.userId == lift(id)).map(_.username)) match {
      case Nil => Option.empty
      case x :: _ => Option(x)
    }

  /**
    * Update an account by decreasing its balance.
    *
    * @param user   the user whose account will be updated
    * @param amount the amount to decrease
    * @return the new balance
    */
  def purchase(user: String, amount: Double): Double =
    ctx.run(query[Account]
      .filter(_.username == lift(user))
      .update(u => u.balance -> (u.balance - lift(amount)))
      .returning(_.balance))
}
