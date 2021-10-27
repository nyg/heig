package Chat

object Tokens {
  type Token = Int

  // Terms
  val BONJOUR: Token     =  0
  val JE: Token          =  1
  val MON: Token         = 16
  val SOLDE: Token       = 17

  // Verbs
  val ETRE: Token        =  2
  val VOULOIR: Token     =  3
  val CONNAITRE: Token   = 15
  val COMMANDER: Token   = 18
  val COUTER: Token      = 19
  val APPELER            = 26

  // Operators
  val ET: Token          =  4
  val OU: Token          =  5

  // Products
  val BIERE: Token       =  6
  val CROISSANT: Token   =  7

  // Brands
  val BRAND: Token       =  8

  // Misc
  val COMBIEN: Token     = 20
  val LE: Token          = 21
  val QUEL: Token        = 22
  val PRIX: Token        = 23
  val DE: Token          = 24
  val ME: Token          = 25

  // Utils
  val PSEUDO: Token      =  9
  val NUM: Token         = 10
  val UNKNOWN: Token     = 11
  val EOL: Token         = 12

  // State of mind
  val ASSOIFFE : Token   = 13
  val AFFAME : Token     = 14
}
