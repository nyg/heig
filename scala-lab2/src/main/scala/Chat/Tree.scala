package Chat

import Data.Products._
import Data.UsersInfo

object Tree {

  /**
    * This sealed trait represents a node of the tree and contains methods to
    * compute it and write its output text in console.
    */
  sealed trait ExprTree {

    /**
      * Compute the price of the current node, then returns it. If the node is
      * not a computational node, the method returns 0.0.
      * For example if we had a "+" node, we would add the values of its two
      * children, then return the result.
      *
      * @return the result of the computation
      */
    def computePrice: Double = this match {
      case ProductQuantity(product, quantity) => product.price * quantity
      case And(e1, e2) => e1.computePrice + e2.computePrice
      case Or(e1, e2) => Math.min(e1.computePrice, e2.computePrice)
      case _ => 0.0
    }

    /**
      * Return the output text of the current node, in order to write it in
      * console.
      *
      * Note: this also implements the logic of the application.
      *
      * @return the output text of the current node
      */
    def reply: String = this match {

      case Thirsty() => "Eh bien, la chance est de votre côté, car nous offrons les meilleures bières de la région !"
      case Hungry() => "Pas de soucis, nous pouvons notamment vous offrir des croissants faits maison !"
      case Information(products) => s"Cela coûte ${products.computePrice}"

      case Identification(pseudo) =>
        UsersInfo.activeUser = pseudo
        s"Bonjour, $pseudo !"

      case Balance() =>
        try {
          s"Le montant actuel de votre solde est de CHF ${UsersInfo.activeBalance}."
        }
        catch {
          case e: IllegalStateException => e.getMessage
        }

      case Command(products) =>
        try {
          "Voici donc %s ! Cela coûte CHF %.1f et votre nouveau solde est de CHF %.1f"
            .format(products.reply, products.computePrice, UsersInfo.purchase(products.computePrice))
        }
        catch {
          case e: IllegalStateException => e.getMessage
        }

      case And(e1, e2) => s"${e1.reply} et ${e2.reply}"
      case Or(e1, e2) => (if (e1.computePrice <= e2.computePrice) e1 else e2).reply
      case ProductQuantity(product, quantity) => s"$quantity $product"
    }
  }

  /** The user expressed that he is thirsty. */
  case class Thirsty() extends ExprTree

  /** The user expressed that he is hungry. */
  case class Hungry() extends ExprTree

  /** The user identified himself. */
  case class Identification(pseudo: String) extends ExprTree

  /** The user asked to know his remaining balance. */
  case class Balance() extends ExprTree

  /** The user bought something. It can be a single product or many (using And and Or). */
  case class Command(products: ExprTree) extends ExprTree

  /** The user asked information about something. It can be a single product or many. */
  case class Information(products: ExprTree) extends ExprTree

  /** These two expressions need to be realized. */
  case class And(e1: ExprTree, e2: ExprTree) extends ExprTree

  /** One of these two expressions needs to be realized (the cheapest one). */
  case class Or(e1: ExprTree, e2: ExprTree) extends ExprTree

  /** Represents one of our products with a desired quantity. */
  case class ProductQuantity(product: Product, quantity: Int) extends ExprTree
}
