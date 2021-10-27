package Data

import scala.collection.mutable

object UsersInfo {

  // Will contain the name of the currently active user; default value is null.
  private var _activeUser: String = _

  // Step 2: create an attribute that will contain each user and its current
  // balance.
  private val accounts: mutable.Map[String, Double] = mutable.Map()

  /**
    * Step 2: update the active user's account by decreasing its balance.
    *
    * @param amount the amount to decrease
    * @return the new balance
    * @throws IllegalStateException if the balance is insufficient
    */
  def purchase(amount: Double): Double = {

    if (amount > activeBalance)
      throw new IllegalStateException(s"Il ne vous reste que $activeBalance, ce n'est pas assez !")

    accounts(activeUser) -= amount
    accounts(activeUser)
  }

  /**
    * Set the active user. If he doesn't have an account we create one for him.
    */
  def activeUser_=(user: String): Unit = {
    if (!accounts.contains(user)) accounts.put(user, 30.0)
    _activeUser = user
  }

  def activeUser: String = _activeUser

  /**
    * Get the balance of the active user.
    *
    * @throws IllegalStateException if there is no active user
    */
  def activeBalance: Double =
    if (_activeUser != null) accounts(_activeUser)
    else throw new IllegalStateException("Veuillez vous identifier !")
}
