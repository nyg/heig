package Chat

class Parser(tokenizer: Tokenizer) {
  import Tree._
  import Chat.Tokens._
  import tokenizer._
  import Data.Products._

  var curUser = ""
  var curTuple: (String, Token) = ("bad", BAD)
  readToken()
  
  def curValue: String = curTuple._1
  def curToken: Token = curTuple._2

  /** Reads the next token and assigns it into the global variable curTuple */
  def readToken(): Unit = curTuple = nextToken()

  /** "Eats" the expected token, or terminates with an error. */
  private def eat(token: Token): String = 
    if (token == curToken) {
      val tmp = curValue
      readToken()
      tmp
    } else expected(token)

  /** Complains that what was found was not expected. The method accepts arbitrarily many arguments of type TokenClass */
  private def expected(token: Token, more: Token*): Nothing =
    fatalError(" expected: " +
      (token :: more.toList).map(tokenClass(_)).mkString(" or ") +
      ", found: " + tokenClass(curToken))

  def fatalError(msg: String): Nothing = {
    throw new Exception(s"Fatal error: $msg")
  }

  /** the root method of the parser: parses an entry phrase */
  def parsePhrases() : ExprTree = {
    if (curToken == BONJOUR) readToken()
    if (curToken == COMBIEN) {
      readToken()
      eat(COUTER)
      QueryCommands(parseCommands())
    }
    else if (curToken == QUEL) {
      readToken()
      eat(ETRE)
      eat(LE)
      eat(PRIX)
      eat(DE)
      QueryCommands(parseCommands())
    }
    else if (curToken == JE) {
      readToken()
      if (curToken == ETRE) {
        readToken()
        if (curToken == ASSOIFE) {
          readToken()
          Thirsty()
        }
        else if (curToken == AFFAME) {
          readToken()
          Hungry()
        }
        else if (curToken == PSEUDO){
          curUser = curValue
          Identification(curValue)
        }
        else expected(ASSOIFE, AFFAME, PSEUDO)
      }       
      else if (curToken == ME) {
        readToken()
        eat(APPELLER)
        val user = eat(PSEUDO)
        Identification(user)
      }
      else if (curToken == VOULOIR)
      {
        readToken()
        if (curToken == COMMANDER) {
          readToken()
          OrderCommands(parseCommands())
        } else if (curToken == CONNAITRE) {
          readToken()
          eat(MON)
          eat(SOLDE)
          SoldQuery()
        }
        else expected(CONNAITRE,COMMANDER)
      }
      else expected(ETRE, ME, VOULOIR)
    }
    else expected(BONJOUR, QUEL, JE, COMBIEN)
  }

  /** Parses the commands, either one, or more separated by ET or OU */
  def parseCommands(): ExprTree = {
    val cmd = parseCommand()
    //readToken() //removed
    if (curToken == ET) {
      readToken()
      And(cmd, parseCommands())
    }
    else if (curToken == OU) {
      readToken()
      Or(cmd, parseCommands())
    }
    else cmd
  }
  /** parses a Command */
  def parseCommand () : ExprTree = {
    if (curToken == NUM) {
      val number = curValue.toInt
      readToken()
      Command (parseProduct(), number)
    }
    else Command (parseProduct(), 1)
  }

  /** parses a Product */
  def parseProduct(): ExprTree = {
    val prodName = eat(PRODUCT)
    val prodBrand = 
      if (curToken == BRAND) eat(BRAND)
      else defaultBrand.getOrElse(prodName, "undefined")

    Product(prodName, prodBrand)
  }

}
