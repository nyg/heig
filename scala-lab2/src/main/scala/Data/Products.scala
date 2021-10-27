package Data

import Chat.Tokens._

object Products {

  case class Product(ptype: Token, brand: String, price: Double) {
    override def toString: String = ptype match {
      case BIERE => s"$brand"
      case CROISSANT => s"croissant $brand"
    }
  }

  // Step 2: here your will have an attribute that will contain the products
  // (e.g. "bière"), their types (e.g. "Boxer"), and their prices (e.g. 2.0).
  val values = List(
    Product(BIERE, "Boxer", 1.0),
    Product(BIERE, "Farmer", 1.0),
    Product(BIERE, "Wittekop", 2.0),
    Product(BIERE, "PunkIPA", 3.0),
    Product(BIERE, "Jackhammer", 3.0),
    Product(BIERE, "Ténébreuse", 4.0),
    Product(BIERE, "Chouffe", 4.0), // quand même…
    Product(CROISSANT, "Maison", 2.0),
    Product(CROISSANT, "Cailler", 2.0)
  )

  // Step 2: You will also have to find a way to store the default type/brand of
  // a product.
  //
  // Comment: the first element is considered as the default one.
  val default: Map[Token, Product] = values.groupBy(_.ptype).map(e => (e._1, e._2.head))

  /**
    * Gets the product with the given type and brand.
    */
  def find(ptype: Token, brand: String): Product = {
    // If the parser has done its job, there will be no NoSuchElementException thrown.
    values.find(p => p.ptype == ptype && p.brand == brand).get
  }

  /** Check if a given brand exists. */
  def hasBrand(brand: String): Boolean =
    values.exists(_.brand == brand)
}
