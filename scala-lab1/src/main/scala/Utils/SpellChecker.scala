package Utils

import scala.util.Try

object SpellChecker {

  /**
    * Calculate the Levenshtein distance between two words.
    *
    * @param s1 the first word
    * @param s2 the second word
    * @return an integer value, which indicates the Levenshtein distance between
    *         "s1" and "s2"
    */
  def stringDistance(s1: String, s2: String): Int = {

    def levenshtein(acc: Int, i: Int, j: Int): Int =
      (i, j) match {
        case (0, l) => acc + l
        case (k, 0) => acc + k
        case _ => min(
          levenshtein(acc + 1, i - 1, j),
          levenshtein(acc + 1, i, j - 1),
          levenshtein(acc + (if (s1(i - 1) == s2(j - 1)) 0 else 1), i - 1, j - 1)
        )
      }

    def min(nums: Int*): Int = nums.min

    levenshtein(0, s1.length, s2.length)
  }

  /**
    * Get the syntactically closest word in the dictionary from the given
    * misspelled word, using the "stringDistance" function. If the word is a
    * number, this function just returns it.
    *
    * @param misspelledWord the misspelled word to correct
    * @return the closest word from "misspelledWord"
    */
  def getClosestWordInDictionary(misspelledWord: String): String =
    misspelledWord match {
      case x if Try(x.toInt).isSuccess => x // nombre
      case x if x startsWith "_" => x // pseudo
      case x => Dictionary.dictionary.map(e => (stringDistance(e._1, x), e._2)).min._2
    }
}
