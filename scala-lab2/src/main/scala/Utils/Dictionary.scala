package Utils

import Data.Products

/**
  * Contains the dictionary of the application, which is used to validate,
  * correct and normalize words entered by the user.
  */
object Dictionary {

  // This dictionary is a Map object that contains valid words as keys and their normalized equivalents as values (e.g.
  // we want to normalize the words "veux" and "aimerais" in on unique term: "vouloir").
  val dictionary: Map[String, String] = Map(
    "bonjour" -> "bonjour",
    "hello" -> "bonjour",
    "yo" -> "bonjour",
    "je" -> "je",
    "j" -> "je",
    "m" -> "me",
    "me" -> "me",
    "mon" -> "mon",
    "solde" -> "solde",
    "appelle" -> "appelle",
    "est" -> "etre",
    "suis" -> "etre",
    "veux" -> "vouloir",
    "voudrais" -> "vouloir",
    "aimerais" -> "vouloir",
    "connaître" -> "connaitre",
    "connaitre" -> "connaitre",
    "savoir" -> "connaitre",
    "coûte" -> "couter",
    "coûtent" -> "couter",
    "bière" -> "biere",
    "bières" -> "biere",
    "croissant" -> "croissant",
    "croissants" -> "croissant",
    "et" -> "et",
    "ou" -> "ou",
    "le" -> "le",
    "de" -> "de",
    "prix" -> "prix",
    "quel" -> "quel",
    "combien" -> "combien",
    "assoiffé" -> "assoiffe",
    "assoiffée" -> "assoiffe",
    "affamé" -> "affame",
    "affamée" -> "affame",
    "commander" -> "commander",
  ) ++ Products.values.map(p => p.brand -> p.brand) // adding brands
}
