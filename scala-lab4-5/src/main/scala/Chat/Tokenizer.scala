package Chat

import Chat.Tokens._
import Utils.Dictionary.dictionary
import Utils.SpellChecker._

class Tokenizer(input: String) {

  var tokens: Array[(String, Token)] = Array()
  var currentTokenIndex: Int = -1

  def tokenize(): Unit = {
    val words = input
      .trim()
      .replaceAll("[.|,|!|?|*]", " ") // Remove punctuation.
      .replaceAll(" +|[']", " ") // Remove multiple spaces and replace apostrophes by a space.
      .split(" ")
      .map(_.toLowerCase())

    /** Get each word's occurence in the dictionary or check for the closest word if it is not contained in the dictionary.*/
    val fromDictionnary = words.map(w => dictionary.getOrElse(w, getClosestWordInDictionary(w)))

    tokens = fromDictionnary.map(t => (t, t match {
      case "bonjour" => BONJOUR
      case "je" => JE
      case "etre" => ETRE
      case "assoife" => ASSOIFE
      case "affame" => AFFAME
      case "vouloir" => VOULOIR
      case "et" => ET
      case "ou" => OU
      case "biere" => PRODUCT
      case "farmer" => BRAND
      case "tenebreuse" => BRAND
      case "boxer" => BRAND
      case "wittekop" => BRAND
      case "punkipa" => BRAND
      case "jackhammer" => BRAND
      case "croissant" => PRODUCT
      case "maison" => BRAND
      case "cailler" => BRAND
      case "svp" => SVP
      case "commander" => COMMANDER
      case "connaitre" => CONNAITRE
      case "combien" => COMBIEN
      case "couter" => COUTER
      case "mon" => MON
      case "solde" => SOLDE
      case "quel" => QUEL
      case "le" => LE
      case "prix" => PRIX
      case "de" => DE
      case "me" => ME
      case "appeller" => APPELLER
      case p if p.startsWith("_") && p.length > 1 => PSEUDO // If the word starts with '_' and has more than one character it is a pseudonym.
      case n if n.forall(Character.isDigit) => NUM // If every character is a number, the word thus is a number.
      case _ => UNKNOWN
    }))
  }

  def nextToken(): (String, Token) = {
    currentTokenIndex += 1

    if (currentTokenIndex < tokens.length) {
      tokens(currentTokenIndex)
    } else {
      ("EOL", EOL)
    }
  }

  def tokenClass(token:Int) :String = token match {
    case BONJOUR => "bonjour"
    case JE => "je"
    case ETRE => "etre"
    case VOULOIR => "vouloir"
    case ET => "et"
    case OU => "ou"
    case PRODUCT => "product"
    case BRAND => "brand"
    //case UNKNOWN => "unknown"
    case PSEUDO => "pseudo"
    case NUM => "num"
    case EOL => "eol"
    case SVP => "svp"
    case COMMANDER => "commander"
    case CONNAITRE => "connaitre"
    case MON => "mon"
    case SOLDE => "solde"
    case COMBIEN => "combien"
    case COUTER => "couter"
    case ASSOIFE => "assoife"
    case AFFAME => "affame"
    case QUEL => "quel"
    case LE => "le"
    case PRIX => "prix"
    case DE => "de"
    case ME => "me"
    case APPELLER => "appeller"
  }
}
