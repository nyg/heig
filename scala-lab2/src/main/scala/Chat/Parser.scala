package Chat

import Chat.Tokens._
import Chat.Tree._
import Data.Products
import Data.Products.Product

class Parser(tokenizer: Tokenizer) {

  import tokenizer._

  var curTuple: (String, Token) = ("unknown", UNKNOWN)

  def curValue: String = curTuple._1
  def curToken: Token = curTuple._2

  /** Reads the next token and assigns it into the global variable curTuple. */
  private def readToken(): Unit =
    curTuple = nextToken()

  /**
    * Eats the expected token and returns the value of the previous token, or
    * terminates with an error.
    */
  private def eat(token: Token): (String, Token) =
    if (token == curToken) {
      val previousTuple = curTuple
      readToken()
      previousTuple
    }
    else expected(token)

  /**
    * This method will eat the current token only if it matches the first given
    * token, otherwise it will return false. If the first token is eaten then
    * all remaining tokens are considered as required, meaning an "expected"
    * error will occur if one of them is missing.
    */
  private def tryEat(tokens: Token*): Boolean =
    if (curToken == tokens.head) {
      tokens.foreach(eat)
      true
    }
    else false

  /**
    * Complains that what was found was not expected. The method accepts
    * arbitrarily many arguments of type TokenClass
    *
    * BONUS: find a way to display the string value of the tokens (e.g. "BIERE")
    * instead of their integer value (e.g. 6).
    */
  private def expected(token: Token, more: Token*): Nothing = {

    // Use reflexion to create a map of Token -> Token Name.
    val fields = Tokens.getClass.getDeclaredFields
      .filter(_.getType == classOf[Int])
      .map(f => {
        f.setAccessible(true)
        f.getInt(Tokens) -> f.getName
      })
      .toMap

    fatalError(" expected: %s, found: %s".format(
      token +: more map fields mkString " or ", // 😅
      fields(curToken)))
  }

  def fatalError(msg: String): Nothing = {
    println("Fatal error", msg)
    new Exception().printStackTrace()
    sys.exit(1)
  }

  /** Root method of the parser: parses the whole phrase entered by the user. */
  def parsePhrases(): ExprTree = {

    tryEat(BONJOUR)

    if (tryEat(JE))

      if (tryEat(ETRE))
        if (tryEat(ASSOIFFE)) Thirsty()
        else if (tryEat(AFFAME)) Hungry()
        else if (curToken == PSEUDO) parseIdentification()
        else expected(ASSOIFFE, AFFAME, PSEUDO)

      else if (tryEat(ME, APPELER))
        if (curToken == PSEUDO) parseIdentification()
        else expected(PSEUDO)

      else if (tryEat(VOULOIR))
        if (tryEat(CONNAITRE)) parseBalance()
        else if (tryEat(COMMANDER)) Command(parseProductList())
        else expected(CONNAITRE, COMMANDER)

      else
        expected(ETRE, VOULOIR)

    else if (tryEat(COMBIEN, COUTER) || tryEat(QUEL, ETRE, LE, PRIX, DE))
      Information(parseProductList())

    else
      expected(BONJOUR, JE, COMBIEN, QUEL)
  }

  /** Parses an identification request. */
  private def parseIdentification(): Identification =
    Identification(eat(PSEUDO)._1)

  /** Parses a balance request. */
  private def parseBalance(): ExprTree = {
    eat(MON)
    eat(SOLDE)
    Balance()
  }

  /** Parses a product list (i.e. P1 [AND/OR P2]*. */
  private def parseProductList(): ExprTree = {

    @scala.annotation.tailrec
    def parseOperators(previous: ExprTree): ExprTree = eat(curToken)._2 match {
      case ET => parseOperators(And(previous, parseProductQuantity()))
      case OU => parseOperators(Or(previous, parseProductQuantity()))
      case _ => previous
    }

    parseOperators(parseProductQuantity())
  }

  /** Parses a quantity and the associated product and eventual brand. */
  private def parseProductQuantity(): ProductQuantity = {

    val quantity = eat(NUM)._1.toInt

    if (curToken == BIERE || curToken == CROISSANT)
      ProductQuantity(parseProduct(), quantity)
    else
      expected(BIERE, CROISSANT)
  }

  /**
    * Parses a product type and its optional brand. Note that the return class
    * is not a subclass of ExprTree.
    */
  private def parseProduct(): Product = {

    val productType = eat(curToken)._2

    if (curToken == BRAND)
      Products.find(productType, eat(BRAND)._1)
    else
      Products.default(productType)
  }

  // Start the process by reading the first token.
  readToken()
}
