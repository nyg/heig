package Utils

/**
* Contains the dictionary of the application, which is used to validate, correct and normalize words entered by the
* user.
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
    "suis" -> "etre",
    "veux" -> "vouloir",
    "aimerais" -> "vouloir",
    "assoifé" -> "assoife",
    "assoifée" -> "assoife",
    "affamé" -> "affame",
    "affamée" -> "affame",
    "bière" -> "biere",
    "bières" -> "biere",
    "farmer" -> "farmer",  // add other types of beers here
    "wittekop" ->  "wittekop",
    "punkipa" -> "punkipa",
    "jackhammer" -> "jackhammer",
    "boxer" -> "boxer",
    "ténébreuse" -> "tenebreuse",
    "croissant" -> "croissant",
    "cailler" -> "cailler",
    "maison" -> "maison",
    "commander" -> "commander",
    "et" -> "et",
    "ou" -> "ou",
    "svp" -> "svp",
    "stp" -> "svp",
    "connaître" -> "connaitre",
    "combien" -> "combien",
    "coûte" -> "couter",
    "coûtent" -> "couter",
    "mon" -> "mon",
    "solde" -> "solde",
    "de" -> "de",
    "quel" -> "quel",
    "le" -> "le",
    "prix" -> "prix",
    "est" -> "etre",
    "appelle" -> "appeller",
    "me" -> "me",
    "m" -> "me"
  )
}
