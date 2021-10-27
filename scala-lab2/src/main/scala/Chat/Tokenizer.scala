package Chat

import Chat.Tokens._
import Data.Products
import Utils.Dictionary.dictionary
import Utils.SpellChecker._

class Tokenizer(input: String) {

  var tokens: Array[(String, Token)] = Array()
  var currentTokenIndex: Token = -1

  private def isPseudo(s: String): Boolean =
    s.startsWith("_") && s.length > 1

  private def getTokenFromString(s: String): Token = s match {
    case "bonjour" => BONJOUR
    case "je" => JE
    case "me" => ME
    case "appelle" => APPELER
    case "etre" => ETRE
    case "vouloir" => VOULOIR
    case "et" => ET
    case "ou" => OU
    case "le" => LE
    case "de" => DE
    case "prix" => PRIX
    case "combien" => COMBIEN
    case "quel" => QUEL
    case "couter" => COUTER
    case "biere" => BIERE
    case "croissant" => CROISSANT
    case "assoiffe" => ASSOIFFE
    case "affame" => AFFAME
    case "connaitre" => CONNAITRE
    case "mon" => MON
    case "solde" => SOLDE
    case "commander" => COMMANDER
    case b if Products.hasBrand(b) => BRAND // If the word is in our product list, it is a brand
    case p if isPseudo(p) => PSEUDO // If the word starts with '_' and has more than one character it is a pseudonym.
    case n if n.forall(Character.isDigit) => NUM // If every character is a number, the word thus is a number.
    case _ => UNKNOWN
  }

  def tokenize(): Unit = {

    val words = input
      .trim()
      .replaceAll("[.,!?*]", " ") // Remove punctuation.
      .replaceAll(" +|[']", " ") // Remove multiple spaces and replace apostrophes by a space.
      .split(" ")
      .filterNot(_.isEmpty)

    // Get each word's occurence in the dictionary or check for the closest word if it is not contained in the dictionary.
    val fromDictionnary = words.map(w => dictionary.getOrElse(w, getClosestWordInDictionary(w)))

    tokens = fromDictionnary.map(t => (t match {
      // we change the pseudo by removing the underscore and capitalizing the word
      case w if isPseudo(w) => w.substring(1).capitalize
      case w => w
    }, getTokenFromString(t)))
  }

  def nextToken(): (String, Token) = {
    currentTokenIndex += 1

    if (currentTokenIndex < tokens.length) tokens(currentTokenIndex)
    else ("EOL", EOL)
  }
}
