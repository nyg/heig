package Chat

object Tokens {
  type Token = Int

  // Terms
  val BONJOUR: Token     = 0
  val JE: Token          = 1
  val SVP: Token         = 2
  val MON : Token        = 3
  val SOLDE : Token      = 4
  // Actions
  val ETRE: Token        = 5
  val VOULOIR: Token     = 6
  val COMBIEN : Token    = 7
  val COUTER: Token      = 8
  val COMMANDER : Token  = 9
  val CONNAITRE : Token  = 10
  // Logic Operators
  val ET: Token          = 11
  val OU: Token          = 12
  // Products
  val PRODUCT : Token    = 13
  val BRAND: Token       = 14
  // Util
  val PSEUDO: Token      = 15
  val NUM: Token         = 16
  val EOL: Token         = 17
  val BAD: Token         = 18
  val UNKNOWN: Token     = 19
  // Test
  val ASSOIFE : Token = 20
  val AFFAME : Token = 21

  val QUEL : Token = 22
  val LE: Token = 23
  val PRIX: Token = 24
  val DE: Token = 25
  val ME: Token = 26
  val APPELLER: Token = 27
}
