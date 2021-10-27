package Chat

import Data.Products._
import Data.UsersInfo._

object Tree {

  /**
    * This sealed trait represents a node of the tree and contains methods to compute it and write its output text in console.
    */
  sealed trait ExprTree {
    /**
      * Compute the price of the current node, then returns it. If the node is not a computational node, the method
      * returns 0.0.
      * For example if we had a "+" node, we would add the values of its two children, then return the result.
      * @return the result of the computation
      */
    def computePrice: Double = this match {
      case Product(name, brand) => price(name, brand)
      case Command(product, number) => number * product.computePrice
      case And(left, right) => left.computePrice + right.computePrice
      case Or(left, right) => math.min(left.computePrice, right.computePrice)
      case OrderCommands(order) => order.computePrice
      case QueryCommands(order) => order.computePrice
      case _ => throw new Exception("can't evaluate price on " + this)//Changed
    }

    /**
      * Return the output text of the current node, in order to write it in console.
      * @return the output text of the current node
      */
    def reply: String = this match {
      case Identification (name: String) => {
        setActiveUser(name)
        addAccount(name, 30)
        "Bonjour, " + name.substring(1) + " !"
      }
      case Product(name, brand) => if (name == "biere") brand else name + " " + brand
      case Command(product, number) => number.toString + " " + product.reply
      case And(left, right) => left.reply + " et " + right.reply
      case Or(left, right) => {
        val leftPrice = left.computePrice
        val rightPrice = right.computePrice
        if (leftPrice < rightPrice) left.reply
        else right.reply
      }
      case OrderCommands(commands) =>
        if (getActiveUser == null || !doesAccountExist(getActiveUser)) {
          "Veuillez d'abord vous identifier."
        } else {
          "Voici donc " +
           commands.reply +
           " ! Cela coûte CHF " +
           commands.computePrice +
           " et votre nouveau solde est de CHF " +
           purchase(getActiveUser, commands.computePrice)+
           "."
        }
      case QueryCommands(commands) => "Cela coûte CHF "  + commands.computePrice + "."
      case SoldQuery() =>
        if (getActiveUser == null || !doesAccountExist(getActiveUser)) {
          "Veuillez d'abord vous identifier."
        } else {
          "Le montant actuel de votre solde est de CHF " +
           getAccountBalance(getActiveUser) +
           "."
        }
      // Example cases
      case Thirsty() => "Eh bien, la chance est de votre côté, car nous offrons les meilleures bières de la région !"
      case Hungry() => "Pas de soucis, nous pouvons notamment vous offrir des croissants faits maisons !"
    }

    /**
      * Get the id of the equivalent db exprtype.
      */
    def exprTypeId = this match {
      case Identification(_) => 1
      case QueryCommands(_) => 2
      case OrderCommands(_) => 3
      case SoldQuery() => 4
      case Thirsty() => 5
      case Hungry() => 6
      case _ => 7
    }
  }

  /**
    * Declarations of the nodes' types.
    */
  case class Identification (name: String) extends ExprTree
  case class QueryCommands (commands: ExprTree) extends ExprTree
  case class OrderCommands (commands: ExprTree) extends ExprTree
  case class SoldQuery() extends ExprTree
  case class Product(name: String, brand: String) extends ExprTree
  case class Command(product: ExprTree, number: Int) extends ExprTree
  case class And(left: ExprTree, right: ExprTree) extends ExprTree
  case class Or(left: ExprTree, right: ExprTree) extends ExprTree
  // Example cases
  case class Thirsty() extends ExprTree
  case class Hungry() extends ExprTree
}
