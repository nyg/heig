package Utils

/**
  * Contains the functions necessary to calculate the number of *clinks* when n
  * people want to cheers.
  */
object ClinksCalculator {

  /**
    * Calculate the factorial of a given number.
    *
    * @param n the number to compute
    * @return n!
    */
  def factorial(n: Int): Int = {

    // Utilisation d'une fonction recursive terminale
    @scala.annotation.tailrec
    def terminalFactorial(acc: Int, n: Int): Int =
      if (n == 0) acc
      else terminalFactorial(n * acc, n - 1)

    terminalFactorial(1, n)
  }

  /**
    * Calculate the combination of two given numbers.
    *
    * @param n the first number
    * @param k the second number
    * @return n choose k
    */
  def calculateCombination(n: Int, k: Int): Int =
    factorial(n) / (factorial(k) * factorial(n - k))
}
