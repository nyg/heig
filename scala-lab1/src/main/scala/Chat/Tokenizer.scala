package Chat

import Chat.Tokens._
import Utils.SpellChecker._

import scala.collection.mutable
import scala.util.Try

class Tokenizer(input: String) {

  val tokens: mutable.Queue[(String, Token)] = mutable.Queue()

  /**
    * Separate the user's input into tokens.
    */
  def tokenize(): Unit = {

    // fait la connection entre un mot du dictionnaire et un Token
    def getToken(w: String): (String, Token) =
      (w, w match {
        case x if x startsWith "_" => PSEUDO
        case x if Try(x.toInt).isSuccess => NUM
        case "bonjour" => BONJOUR
        case "je" => JE
        case "etre" => ETRE
        case "vouloir" => VOULOIR
        case "et" => ET
        case "ou" => OU
        case "biere" => BIERE
        case "croissant" => CROISSANT
        case _ => UNKNOWN // inclus "svp"
      })

    tokens.addAll(input
      .replaceAll("[^a-zA-Z0-9' _]", "") // élimination des caractères non acceptés
      .replaceAll("'", " ") // remplacement de l'apostrophe en espace
      .replaceAll("\\s{2,}", " ") // élimination des espaces en double
      .split(' ') // découpage de la phrase en mots
      .map(w => getToken(getClosestWordInDictionary(w))))
  }

  /**
    * Get the next token of the user input, or OEL if there is no more token.
    *
    * @return a tuple that contains the string value of the current token, and
    *         the identifier of the token
    */
  def nextToken(): (String, Token) =
    if (tokens.isEmpty) ("EOL", EOL)
    else tokens.dequeue()
}
